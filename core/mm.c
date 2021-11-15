// SPDX-License-Identifier: GPL-2.0-only
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>

#include "mtree.h"
#include "mm.h"
#include "helpers.h"
#include "host_platform.h"
#include "armtrans.h"
#include "guest.h"

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

#ifdef HOSTBLINDING_DEV
static kvm_hyp_region kvm_hyp_regions[MAX_KVM_HYP_REGIONS];
#endif // HOSTBLINDING_DEV

#ifdef HOSTBLINDING_DEV
int add_kvm_hyp_region(uint64_t vaddr, uint64_t paddr, uint64_t size)
{
	int ret, i;

	ret = 0;

	if (size == 0)
		return ret;

	for (i = 0; i < MAX_KVM_HYP_REGIONS; i++) {
		if (kvm_hyp_regions[i].vaddr == 0) {
			kvm_hyp_regions[i].vaddr = vaddr;
			kvm_hyp_regions[i].paddr = paddr;
			kvm_hyp_regions[i].size = size;
			break;
		}
	}
	if (i >= MAX_KVM_HYP_REGIONS)
		ret = -ENOMEM;

	return ret;
}

int remove_kvm_hyp_region(uint64_t vaddr)
{
	int ret, i;

	ret = 0;

	for (i = 0; i < MAX_KVM_HYP_REGIONS; i++) {
		if (kvm_hyp_regions[i].vaddr == vaddr) {
			kvm_hyp_regions[i].vaddr = 0;
			kvm_hyp_regions[i].paddr = 0;
			kvm_hyp_regions[i].size = 0;
			break;
		}
	}
	if (i >= MAX_KVM_HYP_REGIONS)
		ret = -ENOENT;

	return ret;
}

bool is_in_kvm_hyp_region(uint64_t paddr)
{
	int i;

	for (i = 0; i < MAX_KVM_HYP_REGIONS; i++) {
		if (kvm_hyp_regions[i].size != 0) {
			if (paddr >= kvm_hyp_regions[i].paddr &&
				paddr < (kvm_hyp_regions[i].paddr + kvm_hyp_regions[i].size))
				return true;
		}
	}
	return false;
}
#endif // HOSTBLINDING_DEV

void *kern_hyp_va(void *a)
{
	uint64_t p = (uint64_t)a;

	p = (p & ~KERNEL_MAP);
	p = KERNEL_BASE | p;

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

int user_copy(uint64_t dest, uint64_t src, uint64_t count,
	      uint64_t dest_pgd, uint64_t src_pgd)
{
	uint64_t dest_ipa, src_ipa;

	dest_ipa = pt_walk((struct ptable *)dest_pgd, dest, NULL, TABLE_LEVELS);
	src_ipa = pt_walk((struct ptable *)src_pgd, src, NULL, TABLE_LEVELS);

	memcpy((void *)dest_ipa, (void *)src_ipa, count);
	return 0;
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

	if (!guest || !ipa || !len || len % PAGE_SIZE)
		return -EINVAL;

	res = get_range_info(guest, ipa);
	if (res)
		goto use_old;

	if (guest->pd_index == MAX_PAGING_BLOCKS - 1)
		return -ENOSPC;

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

static kvm_memslot *gfn_to_memslot(kvm_guest_t *guest, gfn_t gfn)
{
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
	if (is_share(g, ipa, PAGE_SIZE) > 0)
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

	if (!gpa || (gpa % PAGE_SIZE) || (len % PAGE_SIZE))
		return -EINVAL;

#ifdef HOSTBLINDING_DEV
	/*
	 * Leave in hyp regions mapped by KVM
	 * Such as kernel bss.
	 */
	if (is_in_kvm_hyp_region(paddr))
		return 0;
#endif // HOSTBLINDING_DEV

	guest = (kvm_guest_t *)g;
	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	if (guest == host) {
		/*
		 * Range must be checked to be physically contiguous.
		 * gpa equals to phy.
		 */
		if (!contiguous)
			return -EINVAL;
		if (unmap_range(host->s2_pgd, STAGE2, gpa, len))
			HYP_ABORT();
		return 0;
	}

#ifndef HOSTBLINDING
	return 0;
#endif // HOSTBLINDING

	while (gpap < (gpa + len)) {
		/*
		 * Unmap scattered ranges from host page by page. Guest stage 2 mapping
		 * must be validated and created before entering this functionality.
		 */
		phys = pt_walk(guest->s2_pgd, gpap, NULL, TABLE_LEVELS);
		if (phys == ~0UL)
			goto cont;

		phys &= PAGE_MASK;
		if (unmap_range(host->s2_pgd, STAGE2, phys, PAGE_SIZE))
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

	if (!gpa || (gpa % PAGE_SIZE) || (len % PAGE_SIZE))
		return -EINVAL;

	guest = (kvm_guest_t *)g;
	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	if (guest == host) {
		/*
		 * Range must be checked to be physically contiguous.
		 * gpa equals to phy.
		 */
		if (!contiguous)
			return -EINVAL;
		if (mmap_range(host->s2_pgd, STAGE2, gpa, gpa,
			       len, ((SH_INN<<8)|PAGE_HYP_RW),
			       S2_NORMAL_MEMORY))
			HYP_ABORT();
		return 0;
	}

#ifndef HOSTBLINDING
	return 0;
#endif // HOSTBLINDING

	if ((gpa + len) > guest->ramend)
		return -EINVAL;

	while (gpap < (gpa + len)) {
		/*
		 * Restore scattered ranges page by page. Guest stage 2 mapping must be
		 * maintained until this call has been completed.
		 */
		phys = pt_walk(guest->s2_pgd, gpap, NULL, TABLE_LEVELS);
		if (phys == ~0UL)
			goto cont;

		phys &= PAGE_MASK;
		if (mmap_range(host->s2_pgd, STAGE2, phys, phys,
			       PAGE_SIZE, ((SH_INN<<8)|PAGE_HYP_RW),
			       S2_NORMAL_MEMORY))
			HYP_ABORT();

cont:
		gpap += PAGE_SIZE;
	}
	return 0;
}

#ifdef HOSTBLINDING

int restore_host_mappings(void *gp)
{
	kvm_guest_t *host, *guest = (kvm_guest_t *)gp;
	uint64_t slot_start, slot_end, size;
	uint64_t slot_addr, *pte;
	int i, res;

	if (!guest)
		return -EINVAL;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++) {
		if (!guest->slots[i].slot.npages)
			continue;

		slot_start = fn_to_addr(guest->slots[i].slot.base_gfn);
		size = guest->slots[i].slot.npages * PAGE_SIZE;

		/* See where the slot is in the memory */

		slot_end = slot_start;
		while (slot_end <= (slot_start + size)) {
			slot_addr = pt_walk(guest->s2_pgd, slot_end, &pte, 4);
			if (slot_addr == ~0UL)
				goto cont;
			/*
			 * Now we know that the slot_end points to a page
			 * at addr that was stolen from the host. Restore
			 * it and make sure there is no information leak
			 * on it.
			 */
			memset((void *)slot_addr, 0, PAGE_SIZE);
			res = mmap_range(host->s2_pgd, STAGE2, slot_addr, slot_addr,
					 PAGE_SIZE, PAGE_HYP_RWX, S2_NORMAL_MEMORY);
			if (res)
				HYP_ABORT();
cont:
			slot_end += PAGE_SIZE;
		}
	}
	return 0;
}

bool map_back_host_page(uint64_t vmid, uint64_t ttbr0_el1, uint64_t far_el2)
{
	kvm_guest_t *guest = NULL;
	kvm_guest_t *host = NULL;
	uint64_t ipa;

	/* Check if we have such guest */
	guest = get_guest_by_s1pgd((struct ptable *)ttbr0_el1);
	if (guest == NULL)
		return false;

#ifndef HOSTBLINDING_DEV
	/*
	 * Data abort from the owning process of VM.
	 * Feature under development. Do not allow
	 * mapping back the host page unless
	 * HOSTBLINDING_DEV is defined.
	 */
	HYP_ABORT();
#endif //HOSTBLINDING_DEV

	/*
	 * Stage 1 pgd of the process that owns the VM.
	 * We should be able to find the IPA from there.
	 */
	ipa = pt_walk(guest->s1_pgd, far_el2, NULL, TABLE_LEVELS);
	if (ipa == ~0UL)
		return false;

	host = get_guest(vmid);
	if (host == NULL)
		return false;

	ipa = ipa & PAGE_MASK;

	/* 1:1 mapping - TODO the parameters from platform map */
	if (mmap_range(host->s2_pgd, STAGE2, ipa, ipa,
		       PAGE_SIZE, ((SH_NO<<8)|PAGE_HYP_RWX), S2_NORMAL_MEMORY))
		HYP_ABORT();

	return true;
}

#else

bool map_back_host_page(uint64_t vmid, uint64_t ttbr0_el1,
		        uint64_t far_el2)
{
	return false;
}

#endif //HOSTBLINDING
