// SPDX-License-Identifier: GPL-2.0-only
#include <stdbool.h>

#include "mm.h"
#include "helpers.h"
#include "host_platform.h"
#include "armtrans.h"
#include "guest.h"
#include "hvccall-defines.h"
#include "include/generated/asm-offsets.h"

uint64_t __kvm_host_data[PLATFORM_CORE_COUNT];
uint64_t hyp_text_start;
uint64_t hyp_text_end;
uint64_t core_lock;

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

	/*LOG("user_copy (0x%lx)p:0x%lx -> (0x%lx)p:0x%lx\n",
		src, src_ipa, dest, dest_ipa);*/

	memcpy((void *)dest_ipa, (void *)src_ipa, count);

	return 0;
}

#ifdef HOSTBLINDING

int blind_host(uint64_t ipa, uint64_t paddr, size_t len)
{
	/* Leave out the 'virt' device space */
	if (ipa < 0x40000000) {
		LOG("Not blinding device at IPA 0x%lx PADDR %0xlx\n",
		     ipa, paddr);
		return 0;
	}

#ifdef HOSTBLINDING_DEV
	/*
	 * Leave in hyp regions mapped by KVM
	 * Such as kernel bss.
	 */
	if (is_in_kvm_hyp_region(paddr))
		return 0;
#endif // HOSTBLINDING_DEV

	return unmap_range(NULL, STAGE2, paddr, len);
}

#endif
