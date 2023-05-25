// SPDX-License-Identifier: GPL-2.0-only
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "guest.h"
#include "helpers.h"
#include "kvms_rs.h"
#include "kic.h"
#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "signature_pub.h"

#ifdef KIC_ENABLE
#define CHECKRES(x) (if (x != MBEDTLS_EXIT_SUCCESS) return -EFAULT;)
__attribute__((__section__(".el1_hyp_img")))
uint32_t el1_hyp_img[1024] = {
#include "generated/ic_loader.hex"
};
__attribute__((__section__(".el1_hyp_data")))
uint32_t el1_hyp_data[1024];

#define VA_EL1_HYP_IMAGE ((uint64_t) el1_hyp_img)
#define PA_EL1_HYP_IMAGE ((uint64_t) el1_hyp_img)
#define VA_EL1_HYP_DATA  (VA_EL1_HYP_IMAGE + PAGE_SIZE)
#define PA_EL1_HYP_DATA ((uint64_t) el1_hyp_data)

DEFINE_SPINLOCK(kic_lock);

/* Guest Authenticated Data */
static gad_t *gad;

void init_kic(kvm_guest_t *guest)
{
	guest->kic_status = KIC_NOT_STARTED;
}

void kic_free(kvm_guest_t *guest)
{
	if (guest->kic_status < KIC_PASSED) {
		/* KIC process died, remote the lock
		 */
		guest->kic_status = KIC_FAILED;
		spin_unlock(&kic_lock);
	}
}

int handle_icldr_mapping(kvm_guest_t *guest, uint64_t vaddr,
			 uint64_t *paddr, uint64_t len, uint64_t *prot)
{
	int res = 0;

	if (guest->kic_status < KIC_RUNNING) {
		guest->kic_status = KIC_RUNNING;
		*paddr = PA_EL1_HYP_IMAGE;
		if (len > PAGE_SIZE) {
			/* Executable area of ICL cannot be more than 1 page */
			ERROR("invalid ICL size 0x%llx\n", len);
			return -EFAULT;
		}
		/* Executable page of ICL must be read only */
		*prot = (*prot & ~S2AP_MASK) | S2AP_READ;

		return 0;
	}
	if (guest->kic_status >= KIC_VERIFIED_OK) {
		/* Unmap ICL */
		res = unmap_range(guest, STAGE2, VA_EL1_HYP_IMAGE, PAGE_SIZE);
		res |= unmap_range(guest, STAGE2, VA_EL1_HYP_DATA, PAGE_SIZE);

		if (res)
			return -EFAULT;

		if (guest->kic_status == KIC_VERIFIED_OK)
			guest->kic_status = KIC_PASSED;
		else
			guest->kic_status = KIC_FAILED;
		 spin_unlock(&kic_lock);
	} else {
		/* No executable pages (other than el1_hyp_img page) until
		 * KIC is complete
		 */
		if ((*prot & S2_EXEC_NONE) != S2_EXEC_NONE) {
			ERROR("invalid prot bits 0x%llx on addr 0x%llx\n",
			       *prot, vaddr);
			return -EFAULT;
		}
	}

	return res;
}

static int guest_calc_hash(kvm_guest_t *guest, mbedtls_sha256_context *ctx,
		     uint64_t ipa, size_t len)
{
	uint64_t page_len;
	uint64_t paddr;
	int ret = 0;

	while (len) {
		page_len = (len > PAGE_SIZE) ?  PAGE_SIZE : len;
		paddr = pt_walk(guest, STAGE2, ipa, 0);
		if (paddr == ~0UL) {
			return -EINVAL;
		}
		ret = mbedtls_sha256_update_ret(ctx, (void *) paddr, page_len);
		if (ret != MBEDTLS_EXIT_SUCCESS)
			return ret;

		ipa += page_len;
		len -= page_len;
	}
	return ret;
}

int remap_icloader(void *g, uint64_t image)
{
	kvm_guest_t *guest = g;
	uint64_t ret_addr = read_reg(ELR_EL2) & 0xfff;

	if (guest->kic_status != KIC_RUNNING) {
		ERROR("remap_icloder() call\n");
		guest->kic_status = KIC_VERIFIED_FAIL;
		return KIC_FATAL;
	}
	if (unmap_range(guest, STAGE2, image, PAGE_SIZE))
		return KIC_FATAL;

	if (mmap_range(guest, STAGE2, VA_EL1_HYP_IMAGE, PA_EL1_HYP_IMAGE,
			PAGE_SIZE,
			S2_SH_INN | S2AP_READ |
			S2_MEM_TYPE_MASK | S2_IWB,
			KERNEL_MATTR))
		return KIC_FATAL;

	if (mmap_range(guest, STAGE2, VA_EL1_HYP_DATA, PA_EL1_HYP_DATA,
			PAGE_SIZE,
			S2_EXEC_NONE | S2_SH_INN | S2AP_RW |
			S2_MEM_TYPE_MASK | S2_IWB,
			KERNEL_MATTR)) {
		unmap_range(guest, STAGE2, VA_EL1_HYP_IMAGE, PAGE_SIZE);
		return KIC_FATAL;
	}

	ret_addr |=  VA_EL1_HYP_IMAGE & ~0xfff;

	write_reg(ELR_EL2, ret_addr);
	return 0;
}

int image_check_init(void *g, uint64_t start_page)
{
	kvm_guest_t *guest = g;
	mbedtls_sha256_context ctx;
	uint8_t hash[32];
	int ret;
	int i;

	if (guest->kic_status != KIC_RUNNING) {
		ERROR("Illegal image_check_init() call\n");
		guest->kic_status = KIC_VERIFIED_FAIL;
		return KIC_FATAL;
	}

	gad = malloc(sizeof(gad_t));
	if (!gad) {
		ERROR("No memory\n");
		return KIC_ERROR;
	}

	copy_from_guest(guest, STAGE2, gad, (void *) start_page,
			sizeof(gad_t));

	if (gad->macig != 0x4e474953) {
		ERROR("No signature magic\n");
		free (gad);
		gad = NULL;
		guest->kic_status = KIC_VERIFIED_FAIL;
		return KIC_ERROR;
	}
	/* Check guest certifivate */
	ret = mbedtls_sha256_starts_ret(&ctx, 0);
	if (ret != MBEDTLS_EXIT_SUCCESS)
		panic("mbedtls_sha256_starts_ret %d", ret);

	ret = mbedtls_sha256_update_ret(&ctx, (void *) &gad->cert,
					offsetof(guest_cert_t, signature));

	if (ret != MBEDTLS_EXIT_SUCCESS)
		panic("mbedtls_sha256_update_ret %d", ret);

	ret = mbedtls_sha256_finish_ret(&ctx, hash);
	if (ret != MBEDTLS_EXIT_SUCCESS)
		panic("mbedtls_sha256_finish_ret %d", ret);

	for (i = 0; i < KIC_IMAGE_COUNT; i++)
		if (gad->images[i].size > KIC_MAX_IMAGE_SIZE) {
			ERROR("Too big image to check\n");
			free (gad);
			gad = NULL;
			guest->kic_status = KIC_VERIFIED_FAIL;
			return KIC_ERROR;
		}

	if (do_ecdsa((void *) (void *)gad->cert.signature, hash, signature_pub,
			sizeof(signature_pub))) {
		ERROR("kernel integrity check failed for vmid %d\n",
		      guest->vmid);
		guest->kic_status = KIC_VERIFIED_FAIL;
		return KIC_ERROR;
	}

	 /* Check guest authenticated data */
	ret = mbedtls_sha256_starts_ret(&ctx, 0);
	if (ret != MBEDTLS_EXIT_SUCCESS)
		panic("mbedtls_sha256_starts_ret %d", ret);

	ret = mbedtls_sha256_update_ret(&ctx, (void *)gad,
					offsetof(gad_t, signature));
	if (ret != MBEDTLS_EXIT_SUCCESS)
		panic("mbedtls_sha256_update_ret %d", ret);

	ret = mbedtls_sha256_finish_ret(&ctx, hash);
	if (ret != MBEDTLS_EXIT_SUCCESS)
		panic("mbedtls_sha256_finish_ret %d", ret);

	if (do_ecdsa((void *) (void *)gad->signature, hash, gad->cert.sign_key.key, gad->cert.sign_key.size)) {
		ERROR("kernel integrity check failed for vmid %d\n",
		      guest->vmid);
		guest->kic_status = KIC_VERIFIED_FAIL;
		return KIC_ERROR;
	}

	return 0;
}

int check_guest_image(void *g, uint64_t laddr)
{
	mbedtls_sha256_context ctx;
	kvm_guest_t *guest = g;
	uint8_t hash[32];
	uint64_t *load_addr = (uint64_t *) laddr;
	int i;
	int ret;

	if (guest->kic_status != KIC_RUNNING) {
		ERROR("Illegal icheck_guest_image() call\n");
		if (gad)
			free (gad);
		gad = NULL;
		guest->kic_status = KIC_VERIFIED_FAIL;
		return -KIC_FATAL;
	}

	ret = mbedtls_sha256_starts_ret(&ctx, 0);
	if (ret != MBEDTLS_EXIT_SUCCESS)
		panic("mbedtls_sha256_starts_ret %d", ret);

	for (i = 0; i < KIC_IMAGE_COUNT; i++) {
		ret = mbedtls_sha256_starts_ret(&ctx, 0);
		if (ret != MBEDTLS_EXIT_SUCCESS)
			panic("mbedtls_sha256_starts_ret %d", ret);
		ret = guest_calc_hash(guest,
				      &ctx, load_addr[i],
				      gad->images[i].size);
		if (ret != MBEDTLS_EXIT_SUCCESS)
			panic("guest_calc_hash ret %d", ret);
		ret = mbedtls_sha256_finish_ret(&ctx, hash);
		if (ret != MBEDTLS_EXIT_SUCCESS)
			panic("mbedtls_sha256_finish_ret %d", ret);
		if (memcmp(hash, gad->images[i].hash, 32)) {
			printf("Image %x fails\n", gad->images[i].macig);
			guest->kic_status = KIC_VERIFIED_FAIL;
			return -KIC_FATAL;
		}
	}

	if (guest->kic_status != KIC_RUNNING) {
		ERROR("kernel integrity check failed for vmid %d\n",
		      guest->vmid);
		guest->kic_status = KIC_VERIFIED_FAIL;
		ret = KIC_ERROR;
	} else {
		LOG("kernel integrity check passed for vmid %d\n", guest->vmid);
		if (gad->version >= 0x201) {
			if (gad->cert.enc_key.size <= sizeof(guest->pubkey)) {
				guest->pubkey_size = gad->cert.enc_key.size;
				memcpy(guest->pubkey, gad->cert.enc_key.key,
				       guest->pubkey_size);
			}
		}
		set_guest_id(guest, &gad->guest_id, GUEST_ID_LEN);
		guest->kic_status = KIC_VERIFIED_OK;
		ret = 0;
	}
	free (gad);
	gad = 0;
	return ret;
}

int kernel_integrity_ok(const kvm_guest_t *guest)
{
#ifdef DEBUG
	return 1;
#else
	return guest->kic_status == KIC_PASSED;
#endif
}

#else
int remap_icloader(void *g, uint64_t image)
{
	return -ENOTSUP;
}
int image_check_init(void *g, uint64_t start_page)
{
	return -ENOTSUP;
}
void init_kic(kvm_guest_t *guest)
{
}
int check_guest_image(void *g, uint64_t image)
{
	return -ENOTSUP;
}
void kic_free(kvm_guest_t *guest)
{
}
int kernel_integrity_ok(const kvm_guest_t *guest)
{
	return 1;
}
#endif


