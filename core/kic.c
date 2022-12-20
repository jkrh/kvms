// SPDX-License-Identifier: GPL-2.0-only
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "guest.h"
#include "kic.h"
#include "helpers.h"
#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"

#ifndef KIC_DISABLE
#define CHECKRES(x) (if (x != MBEDTLS_EXIT_SUCCESS) return -EFAULT;)
__attribute__((__section__(".el1_hyp_img")))
uint32_t el1_hyp_img[512] = {
#include "generated/ic_loader.hex"
};

spinlock_t kic_lock;
static sign_params_t *sign_params = NULL;

void init_kic(kvm_guest_t *guest)
{
	guest->kic_status = KIC_NOT_STARTED;
}

void kic_free(kvm_guest_t *guest)
{
	if (guest->kic_status <= KIC_PASSED) {
		/* KIC process died, remote the lock
		 */
		guest->kic_status = KIC_FAILED;
		spin_unlock(&kic_lock);
	}
}

int handle_icldr_mapping(kvm_guest_t *guest, uint64_t vaddr, uint64_t *paddr)
{
	int res = 0;
	if (guest->kic_status < KIC_RUNNING) {
		guest->kic_status = KIC_RUNNING;
		*paddr = (uint64_t)&el1_hyp_img;
	}
	if (guest->kic_status >= KIC_VERIFIED_OK) {
		res = unmap_range(guest, STAGE2, (uint64_t) &el1_hyp_img,
				  PAGE_SIZE);
		if (res)
			return res;
		if (guest->kic_status == KIC_VERIFIED_OK)
			guest->kic_status = KIC_PASSED;
		else
			guest->kic_status = KIC_FAILED;
		 spin_unlock(&kic_lock);
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

	if (mmap_range(guest, STAGE2, (uint64_t) &el1_hyp_img,
			(uint64_t) &el1_hyp_img, PAGE_SIZE,
			0x03fc, KERNEL_MATTR))
		return KIC_FATAL;
	ret_addr |=  ((uint64_t) &el1_hyp_img & ~0xfff);

	write_reg(ELR_EL2, ret_addr);
	return 0;
}

int image_check_init(void *g, uint64_t start_page)
{
	kvm_guest_t *guest = g;

	if (guest->kic_status != KIC_RUNNING) {
		ERROR("Illegal image_check_init() call\n");
		guest->kic_status = KIC_VERIFIED_FAIL;
		return KIC_FATAL;
	}

	sign_params = malloc(sizeof(sign_params_t));
	if (!sign_params) {
		ERROR("No memory\n");
		return KIC_ERROR;
	}

	copy_from_guest(guest, sign_params, (void *) start_page,
			sizeof(sign_params_t));

	if (sign_params->macig != 0x4e474953) {
		ERROR("No signature magic\n");
		free (sign_params);
		sign_params = NULL;
		guest->kic_status = KIC_VERIFIED_FAIL;
		return KIC_ERROR;
	}
	if (sign_params->image_size > KIC_MAX_IMAGE_SIZE ||
	    sign_params->dtb_size > KIC_MAX_DTB_SIZE) {
		ERROR("Too big image to check\n");
		free (sign_params);
		sign_params = NULL;
		guest->kic_status = KIC_VERIFIED_FAIL;
		return KIC_ERROR;
	}
	return 0;
}

int check_guest_image(void *g, uint64_t image)
{
	mbedtls_sha256_context ctx;
	kvm_guest_t *guest = g;
	uint8_t hash[32];
	int ret;

	if (guest->kic_status != KIC_RUNNING) {
		ERROR("Illegal icheck_guest_image() call\n");
		if (sign_params)
			free (sign_params);
		sign_params = NULL;
		guest->kic_status = KIC_VERIFIED_FAIL;
		return -KIC_FATAL;
	}

	ret = mbedtls_sha256_starts_ret(&ctx, 0);
	if (ret != MBEDTLS_EXIT_SUCCESS)
		panic("mbedtls_sha256_starts_ret %d", ret);

	ret = mbedtls_sha256_update_ret(&ctx, (void *)sign_params,
			offsetof(sign_params_t, signature));
	if (ret != MBEDTLS_EXIT_SUCCESS)
		panic("mbedtls_sha256_starts_ret %d", ret);

	ret = guest_calc_hash(guest, &ctx, image, sign_params->image_size);
	if (ret != MBEDTLS_EXIT_SUCCESS)
		panic("guest_calc_hash ret %d", ret);

	if (sign_params->dtb) {
		ret = guest_calc_hash(guest, &ctx, sign_params->dtb,
				      sign_params->dtb_size);
		if (ret != MBEDTLS_EXIT_SUCCESS)
			panic("guest_calc_hash ret %d", ret);
	}

	ret = mbedtls_sha256_finish_ret(&ctx, hash);
	if (ret != MBEDTLS_EXIT_SUCCESS)
		panic("mbedtls_sha256_finish_ret %d", ret);

	if (do_ecdsa((void *) (void *)sign_params->signature, hash)) {
		ERROR("kernel integrity check failed for vmid %d\n",
		      guest->vmid);
		guest->kic_status = KIC_VERIFIED_FAIL;
		ret = KIC_ERROR;
	} else {
		memcpy(guest->guest_id, &sign_params->guest_id, GUEST_ID_LEN);
		LOG("kernel integrity check passed for vmid %d\n", guest->vmid);
		guest->kic_status = KIC_VERIFIED_OK;
		ret = 0;
	}
	free (sign_params);
	sign_params = 0;
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


