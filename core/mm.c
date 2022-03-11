// SPDX-License-Identifier: GPL-2.0-only
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>

#include "mtree.h"
#include "mm.h"
#include "helpers.h"
#include "host_platform.h"
#include "armtrans.h"
#include "guest.h"
#include "spinlock.h"

#include "hvccall-defines.h"
#include "hyp_config.h"
#include "hvccall.h"
#include "bits.h"
#include "platform_api.h"

#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"
#include "mbedtls/aes.h"

#define CHECKRES(x) if (x != MBEDTLS_EXIT_SUCCESS) return -EFAULT;

uint64_t __kvm_host_data[PLATFORM_CORE_COUNT];
uint64_t hyp_text_start;
uint64_t hyp_text_end;
extern uint64_t core_lock;

void *kern_hyp_va(void *a)
{
	uint64_t p = (uint64_t)a;

	p &= CALL_MASK;
	p |= KERNEL_BASE;

	return (void *)p;
}

void *get_kvm_host_data(void)
{
	uint64_t hd;

	hd = __kvm_host_data[smp_processor_id()] + read_reg(tpidr_el2);
	return kern_hyp_va((void *)hd);
}

void *get_vcpu_ptr(void)
{
	uint64_t vcpu;
	char *hostd;

	hostd = (char *)get_kvm_host_data();
	if (!hostd)
		return NULL;

	vcpu = *(uint64_t *)(&hostd[HOST_CONTEXT_VCPU]);
	return kern_hyp_va((void *)vcpu);
}

static int __is_range_valid(uint64_t addr_start, size_t len,
			    kvm_memslots *slots, bool is_uaddr)
{
	uint64_t slot_start, slot_end;
	uint64_t addr_end;
	int i;

	addr_end = addr_start + len;

	if (addr_end < addr_start)
		return 0;

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++) {
		if (!slots[i].slot.npages)
			continue;

		if (is_uaddr)
			slot_start = slots[i].slot.userspace_addr;
		else
			slot_start = fn_to_addr(slots[i].slot.base_gfn);

		slot_end = slot_start + (slots[i].slot.npages * PAGE_SIZE);

		if ((addr_start >= slot_start) && (addr_end <= slot_end))
			return 1;
	}
	return 0;
}

int is_range_valid_uaddr(uint64_t addr, size_t len, kvm_memslots *slots)
{
	return __is_range_valid(addr, len, slots, true);
}

int is_range_valid(uint64_t addr, size_t len, kvm_memslots *slots)
{
	return __is_range_valid(addr, len, slots, false);
}

static int compfunc(const void *v1, const void *v2)
{
	const kvm_page_data *val1 = v1;
	const kvm_page_data *val2 = v2;

	if (val1->phys_addr < val2->phys_addr)
		return -1;
	if (val1->phys_addr > val2->phys_addr)
		return 1;
	return 0;
}

kvm_page_data *get_range_info(void *g, uint64_t addr)
{
	kvm_guest_t *guest = (kvm_guest_t *)g;
	kvm_page_data key, *res;

	if (!guest)
		return NULL;

	key.phys_addr = addr;
	res = bsearch(&key, guest->hyp_page_data, guest->pd_index,
		      sizeof(key), compfunc);

	return res;
}

int add_range_info(void *g, uint64_t ipa, uint64_t addr, uint64_t len,
		   uint32_t nonce, uint64_t prot)
{
	kvm_guest_t *guest = (kvm_guest_t *)g;
	mbedtls_sha256_context c;
	kvm_page_data *res;
	bool s = false;
	int ret = 0;

	if (!guest || !ipa || !len || len % PAGE_SIZE) {
		ERROR("invalid arguments: %p %lx %lu\n", guest, ipa, len);
		return -EINVAL;
	}

	/* If for any reason this hits our shares, exit */
	if (is_share(g, ipa, PAGE_SIZE) == 1)
		return 0;

	res = get_range_info(guest, ipa);
	if (res)
		goto use_old;

	if (guest->pd_index == MAX_PAGING_BLOCKS - 1) {
		ERROR("too many paging blocks\n");
		return -ENOSPC;
	}

	s = true;
	res = &guest->hyp_page_data[guest->pd_index];
	res->phys_addr = addr;
	guest->pd_index += 1;

use_old:
	res->nonce = nonce;
	res->vmid = guest->vmid;
	res->len = len;
	if (guest->vmid != HOST_VMID) {
		mbedtls_sha256_init(&c);
		ret = mbedtls_sha256_starts_ret(&c, 0);
		if (ret)
			goto error;
		ret = mbedtls_sha256_update_ret(&c, (void *)addr, len);
		if (ret)
			goto error;
		ret = mbedtls_sha256_update_ret(&c, (void *)&prot, sizeof(uint64_t));
		if (ret)
			goto error;
		ret = mbedtls_sha256_finish_ret(&c, res->sha256);
error:
		if (ret) {
			memset(res->sha256, 0, 32);
			res->vmid = 0;
		}
	} else
		memset(res->sha256, 0, 32);

	if (s)
		qsort(guest->hyp_page_data, guest->pd_index, sizeof(kvm_page_data),
		      compfunc);
	dsb();
	isb();

	return ret;
}

void free_range_info(void *g, uint64_t ipa)
{
	kvm_guest_t *guest = (kvm_guest_t *)g;
	kvm_page_data *res;

	res = get_range_info(guest, ipa);
	if (!res)
		return;

	res->vmid = 0;
	memset(res->sha256, 0, 32);
	dsb();
	isb();
}

int verify_range(void *g, uint64_t ipa, uint64_t addr, uint64_t len,
		 uint64_t prot)
{
	kvm_guest_t *guest = (kvm_guest_t *)g;
	mbedtls_sha256_context c;
	kvm_page_data *res;
	uint8_t sha256[32];
	int ret;

	res = get_range_info(guest, ipa);
	if (!res)
		return -ENOENT;

	if (res->vmid != guest->vmid)
		return -EFAULT;

	mbedtls_sha256_init(&c);
	ret = mbedtls_sha256_starts_ret(&c, 0);
	CHECKRES(ret);

	ret = mbedtls_sha256_update_ret(&c, (void *)addr, len);
	CHECKRES(ret);

	ret = mbedtls_sha256_update_ret(&c, (void *)&prot, sizeof(uint64_t));
	CHECKRES(ret);

	ret = mbedtls_sha256_finish_ret(&c, sha256);
	CHECKRES(ret);

	ret = memcmp(sha256, res->sha256, 32);
	if (ret != 0)
		return -EINVAL;

	return 0;
}

kvm_memslot *gfn_to_memslot(void *g, gfn_t gfn)
{
	kvm_guest_t *guest = (kvm_guest_t *)g;
	int i = 0;

	while (i < KVM_MEM_SLOTS_NUM) {
		if ((gfn >= guest->slots[i].slot.base_gfn) &&
		    (gfn < (guest->slots[i].slot.base_gfn +
			    guest->slots[i].slot.npages)))
			return &guest->slots[i].slot;
		i++;
	}
	return NULL;
}

void set_guest_page_dirty(void *g, gfn_t gfn)
{
	kvm_memslot *slot;
	uint64_t *dbm;
	uint64_t bgfn;

	slot = gfn_to_memslot(g, gfn);
	if (slot && slot->dirty_bitmap) {
		dbm = virt_to_phys(slot->dirty_bitmap);
		if (dbm == (uint64_t *)~0UL) {
			ERROR("dirty_bitmap is set but not translatable?\n");
			return;
		}
		bgfn = gfn - slot->base_gfn;
		set_bit_in_mem(bgfn, dbm);
		dsb();
	}
}

int encrypt_guest_page(void *g, uint64_t ipa, uint64_t addr, uint64_t prot)
{
	kvm_guest_t *guest = (kvm_guest_t *)g;
	uint8_t ciphertext[PAGE_SIZE];
	uint8_t stream_block[16];
	uint8_t nonce_counter[16];
	uint32_t nonce;
	size_t ns = 0;
	int res;

	/* If for any reason this hits our shares, exit */
	if (is_share(g, ipa, PAGE_SIZE) == 1)
		return 0;

	/*
	 * FIXME: we need to re-key every 2^32 swaps.
	 */
	res = platform_entropy((uint8_t *)&nonce, 4);
	if (res)
		return -EFAULT;
	memset(&nonce_counter, 0, 16);
	memcpy(&nonce_counter[0], &nonce, 4);
	memcpy(&nonce_counter[4], &ipa, 8);

	/*
	 * We attempt to verify the integrity and the confideality of the
	 * data. We first encrypt the blob with AES CTR and then compute the
	 * hash over the ciphertext. This way the attacker does not get a
	 * chance to play with our ciphertext.
	 */
	res = mbedtls_aes_crypt_ctr(&guest->aes_ctx, PAGE_SIZE, &ns, nonce_counter,
				    stream_block, (void *)addr, ciphertext);
	if (res != MBEDTLS_EXIT_SUCCESS) {
		mbedtls_strerror(res, (char *)ciphertext, 256);
		ERROR("fault encrypting data: %d / %s\n", res, ciphertext);
		return -EFAULT;
	}
	res = add_range_info(guest, ipa, addr, PAGE_SIZE, nonce, prot);
	if (res)
		return res;

	memcpy((void *)addr, ciphertext, PAGE_SIZE);

	set_guest_page_dirty(g, addr_to_fn(ipa));
	return 0;
}

int decrypt_guest_page(void *g, uint64_t ipa, uint64_t addr, uint64_t prot)
{
	kvm_guest_t *guest = (kvm_guest_t *)g;
	uint8_t stream_block[16];
	uint8_t nonce_counter[16];
	uint8_t cleartext[PAGE_SIZE];
	kvm_page_data *pd;
	size_t ns = 0;
	int res;

	/* Verify the block integrity */
	res = verify_range(g, ipa, addr, PAGE_SIZE, prot);
	if (res == -ENOENT)
		return 0;
	if (res)
		return res;

	/* Check if it was ciphertext we verified */
	pd = get_range_info(guest, ipa);
	if (!pd->nonce)
		return 0;

	memset(&nonce_counter, 0, 16);
	memcpy(&nonce_counter[0], &pd->nonce, 4);
	memcpy(&nonce_counter[4], &ipa, 8);

	/* Decrypt it */
	res = mbedtls_aes_crypt_ctr(&guest->aes_ctx, PAGE_SIZE, &ns, nonce_counter,
				    stream_block, (void *)addr, cleartext);
	if (res != MBEDTLS_EXIT_SUCCESS) {
		mbedtls_strerror(res, (char *)cleartext, 256);
		ERROR("fault decrypting data: %d / %s\n", res, cleartext);
		return -EFAULT;
	}

	/* Add the integrity of the cleartext. */
	res = add_range_info(guest, ipa, addr, PAGE_SIZE, 0, prot);
	CHECKRES(res);

	memcpy((void *)addr, cleartext, PAGE_SIZE);
	return 0;
}

int remove_host_range(void *g, uint64_t gpa, size_t len, bool contiguous)
{
	kvm_guest_t *host, *guest;
	uint64_t phys, gpap = gpa;

	if (!gpa || (gpa % PAGE_SIZE) || (len % PAGE_SIZE)) {
		ERROR("gpa %lx, len %d\n", gpa, len);
		return -EINVAL;
	}

	if (len > (SZ_1M * 16)) {
		ERROR("requested region too large\n");
		return -EINVAL;
	}

	guest = (kvm_guest_t *)g;
	if (!guest->s2_host_access)
		return 0;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	if (guest == host) {
		/*
		 * Range must be checked to be physically contiguous.
		 * gpa equals to phy.
		 */
		if (!contiguous) {
			ERROR("region not contiguous\n");
			return -EINVAL;
		}

		if (unmap_range(host, STAGE2, gpa, len))
			HYP_ABORT();
		return 0;
	}

	while (gpap < (gpa + len)) {
		/*
		 * Unmap scattered ranges from host page by page. Guest stage 2 mapping
		 * must be validated and created before entering this functionality.
		 */
		phys = pt_walk(guest, STAGE2, gpap, NULL);
		if (phys == ~0UL)
			goto cont;

		phys &= PAGE_MASK;
		if (unmap_range(host, STAGE2, phys, PAGE_SIZE))
			HYP_ABORT();
cont:
		gpap += PAGE_SIZE;
	}

	return 0;
}

int restore_host_range(void *g, uint64_t gpa, uint64_t len, bool contiguous)
{
	kvm_guest_t *host, *guest;
	uint64_t phys, gpap = gpa;
	int res = 0;

	if (!gpa || (gpa % PAGE_SIZE) || (len % PAGE_SIZE)) {
		ERROR("invalid arguments: gpa %lx, len %d\n", gpa, len);
		return -EINVAL;
	}
	if (len > (SZ_1M * 16)) {
		ERROR("requested region too large\n");
		return -EINVAL;
	}

	guest = (kvm_guest_t *)g;
	if (!guest->s2_host_access)
		return 0;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	if (guest == host) {
		/*
		 * Range must be checked to be physically contiguous.
		 * gpa equals to phy.
		 */
		if (!contiguous) {
			ERROR("region not contiguous\n");
			res = -EINVAL;
			goto out;
		}
		if (mmap_range(host, STAGE2, gpa, gpa, len,
			       (EL1S2_SH|PAGE_HYP_RW),
			       S2_NORMAL_MEMORY))
			HYP_ABORT();

		goto out;
	}

	if ((gpa + len) > guest->ramend) {
		ERROR("region spans beoynd the end of the guest ram\n");
		res = -EPERM;
		goto out;
	}

	while (gpap < (gpa + len)) {
		/*
		 * Restore scattered ranges page by page. Guest stage 2 mapping
		 * must be maintained until this call has been completed.
		 */
		phys = pt_walk(guest, STAGE2, gpap, NULL);
		if (phys == ~0UL)
			goto cont;

		phys &= PAGE_MASK;
		if (mmap_range(host, STAGE2, phys, phys,
			       PAGE_SIZE, (EL1S2_SH|PAGE_HYP_RW),
			       S2_NORMAL_MEMORY))
			HYP_ABORT();

cont:
		gpap += PAGE_SIZE;
	}
out:
	return res;
}

#ifdef HOSTBLINDING

int restore_host_mappings(void *gp)
{
	kvm_guest_t *host, *guest = (kvm_guest_t *)gp;
	uint64_t slot_start, slot_end, size;
	uint64_t slot_addr, phy_addr, rcount;
	int i, res;
	bool use_at = false;
	struct timeval tv1;
	struct timeval tv2;

	if (!guest)
		return -EINVAL;

	if ((uint64_t)guest->EL1S1_0_pgd ==
	    (read_reg(TTBR0_EL1) & TTBR_BADDR_MASK)) {
		LOG("%s using at commands\n", __func__);
		use_at = true;
	}

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	gettimeofday(&tv1, NULL);

	/* Restore the abort instruction if this was a core dump */

	if (guest->fail_addr) {
		/*
		 * FIXME: in the core dump case the page has been opened
		 * before the dumping started. Second call to this function
		 * will restore the failing instruction here, but since the
		 * page was already moved back to the host we probably should
		 * add page ownership check here before writing anything. While
		 * this is happening before the mmdrop(), we want to be sure.
		 */
		memcpy(guest->fail_addr, &guest->fail_inst, 4);
		guest->fail_addr = 0x0;
	}

	rcount = 0;
	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++) {
		if (!guest->slots[i].slot.npages)
			continue;

		if (use_at)
			slot_start = guest->slots[i].slot.userspace_addr;
		else
			slot_start = fn_to_addr(guest->slots[i].slot.base_gfn);

		size = guest->slots[i].slot.npages * PAGE_SIZE;

		/* See where the slot is in the memory */

		slot_end = slot_start;
		while (slot_end <= (slot_start + size)) {
			if (use_at) {
				/* Is it mapped ? */
				slot_addr = (uint64_t)virt_to_ipa((void *)slot_end);
				if (slot_addr == ~0UL)
					goto cont;

				/* Is it blinded ? */
				phy_addr = (uint64_t)virt_to_phys((void *)slot_end);
			} else {
				/* And the same as above */
				slot_addr = pt_walk(guest, STAGE2, slot_end, NULL);
				if (slot_addr == ~0UL)
					goto cont;

				phy_addr = pt_walk(host, STAGE2, slot_addr, NULL);
			}
			/*
			 * Now we know that the slot_end points to a page at
			 * addr that was stolen from the host. Restore it and
			 * make sure there is no information leak on it if this
			 * a release build.
			 *
			 * Shared communication channel data is always left
			 * intact, even in the core dumps.
			 */
			if (phy_addr != ~0UL)
				clean_guest_page((void *)slot_addr);

			res = mmap_range(host, STAGE2, slot_addr, slot_addr,
					 PAGE_SIZE,
					 (EL1S2_SH | PAGE_HYP_RWX),
					 S2_NORMAL_MEMORY);
			if (res)
				HYP_ABORT();
			rcount++;
cont:
			slot_end += PAGE_SIZE;
		}
	}
	gettimeofday(&tv2, NULL);
	LOG("%s %ld pages. Latency was %ldms\n", __func__, rcount,
	   (tv2.tv_usec - tv1.tv_usec) / 1000);

	return 0;
}

bool __map_back_host_page(void *h, void *g, uint64_t far_el2)
{
	kvm_guest_t *host = h;
	kvm_guest_t *guest = g;
	uint64_t ipa, gpa;
	bool res;

	if ((guest == NULL) || (host == NULL))
		return false;

	res = true;
	/*
	 * Stage 1 pgd of the process that owns the VM.
	 * We should be able to find the IPA from there.
	 */
	ipa = pt_walk(guest, STAGE1, far_el2, NULL);
	if (ipa == ~0UL) {
		res = false;
		goto map_back_out;
	}

	/*
	 * Host has 1:1 mapping so the IPA we are dealing with
	 * is actually also physical address. Validate the location.
	 */
	if (!platform_range_permitted(ipa, PAGE_SIZE)) {
		res = false;
		goto map_back_out;
	}

	gpa = patrack_hpa2gpa(guest, ipa);
	LOG("hva: 0x%lx gpa: 0x%lx hpa: 0x%lx\n", far_el2, gpa, ipa);

	ipa = ipa & PAGE_MASK;

	/* 1:1 mapping - TODO the parameters from platform map */
	if (mmap_range(host, STAGE2, ipa, ipa,
		       PAGE_SIZE, ((SH_NO<<8)|PAGE_HYP_RWX), S2_NORMAL_MEMORY))
		HYP_ABORT();

map_back_out:
	return res;
}

#else

bool __map_back_host_page(void *host, void *guest, uint64_t far_el2)
{
	return false;
}

#endif //HOSTBLINDING
