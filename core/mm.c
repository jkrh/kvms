// SPDX-License-Identifier: GPL-2.0-only
#include <stdbool.h>

#include "mm.h"
#include "helpers.h"
#include "host_platform.h"
#include "armtrans.h"
#include "guest.h"
#include "hvccall-defines.h"
#include "hyp_config.h"
#include "hvccall.h"
#include "bits.h"

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

#ifdef HOSTBLINDING

int remove_host_range(uint64_t paddr, size_t len)
{
	kvm_guest_t *guest = NULL;
#ifdef HOSTBLINDING_DEV
	/*
	 * Leave in hyp regions mapped by KVM
	 * Such as kernel bss.
	 */
	if (is_in_kvm_hyp_region(paddr))
		return 0;
#endif // HOSTBLINDING_DEV
	guest = get_guest(HOST_VMID);

	return unmap_range(guest->s2_pgd, STAGE2, paddr, len);
}

int restore_host_range(uint64_t gpa, uint64_t len)
{
	kvm_guest_t *guest = NULL;
	kvm_guest_t *host = NULL;
	uint64_t phys, gpap = gpa;
	uint32_t vmid;

	vmid = get_current_vmid();
	if (vmid == HOST_VMID)
		return 0;

	guest = get_guest(vmid);
	if (!guest)
		return -EINVAL;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	while (gpap < (gpa + (len * PAGE_SIZE))) {
		phys = pt_walk(guest->s2_pgd, gpa, NULL, TABLE_LEVELS);
		if (phys == ~0UL)
			goto cont;

		phys &= PAGE_MASK;
		if (mmap_range(host->s2_pgd, STAGE2, phys, phys,
			       PAGE_SIZE, ((SH_NO<<8)|PAGE_HYP_RWX),
			       S2_NORMAL_MEMORY))
			HYP_ABORT();
cont:
		gpap += PAGE_SIZE;
	}
	return 0;
}

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
			if (slot_addr == ~0UL) {
				slot_end += PAGE_SIZE;
				continue;
			}
			if (pte && bit_raised(*pte, PTE_SHARED)) {
				slot_end += PAGE_SIZE;
				continue;
			}
			/*
			 * Now we know that the slot_end points to a page
			 * at addr that was stolen from the host. Restore
			 * it and make sure there is no information leak
			 * on it.
			 * Note: devices better not have s2 maps. Only
			 * virtio or regular pagefaulting will work.
			 */
			memset((void *)slot_addr, 0, PAGE_SIZE);
			res = mmap_range(host->s2_pgd, STAGE2, slot_addr, slot_addr,
					 PAGE_SIZE, PAGE_HYP_RWX, S2_NORMAL_MEMORY);
			if (res)
				HYP_ABORT();

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
