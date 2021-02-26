// SPDX-License-Identifier: GPL-2.0-only
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "helpers.h"
#include "mtree.h"
#include "guest.h"
#include "armtrans.h"
#include "hvccall.h"
#include "mm.h"
#include "bits.h"

#include "include/generated/asm-offsets.h"

#ifndef KVM_ARCH
#define KVM_ARCH 0
#define KVM_ARCH_VMID 0
#define KVM_ARCH_PGD 0
#endif

#define TTBR_BADDR_MASK	0x0000FFFFFFFFFFFEUL

/*
 * FIXME: calculate vmid offset
 * properly in asm_offsets.c
 */
#ifndef KVM_ARCH_VMID_OFFT
#define KVM_ARCH_VMID_OFFT 0
#endif

#define _KVM_GET_ARCH(x) ((char *)x + KVM_ARCH)
#define _KVM_GET_VMID(x) (_KVM_GET_ARCH((char *)x) + \
			  KVM_ARCH_VMID + KVM_ARCH_VMID_OFFT)

#define KVM_GET_VMID(x) (*(uint32_t *)_KVM_GET_VMID(x))
#define KVM_GET_PGD_PTR(x) (uint64_t *)(_KVM_GET_ARCH((char *)x) + KVM_ARCH_PGD)

static kvm_guest_t guests[MAX_GUESTS];

kvm_guest_t *get_free_guest()
{
	int i;

	for (i = 0; i < MAX_GUESTS; i++) {
		if (!guests[i].s2_pgd)
			return &guests[i];
	}
	return NULL;
}

kvm_guest_t *get_guest(uint64_t vmid)
{
	kvm_guest_t *guest = NULL;
	int i;

	if (vmid != HOST_VMID) {
		for (i = 0; i < MAX_GUESTS; i++) {
			if (guests[i].kvm &&
			   (vmid == (uint64_t)KVM_GET_VMID(guests[i].kvm))) {
				guests[i].vmid = vmid;
				guest = &guests[i];
				goto out;
			}
		}
	} else {
		for (i = 0; i < MAX_GUESTS; i++) {
			if (guests[i].vmid == HOST_VMID) {
				guest = &guests[i];
				goto out;
			}
		}
		guest = get_free_guest();
		guest->vmid = HOST_VMID;
	}
out:
	return guest;
}

int update_guest_state(guest_state_t state)
{
	kvm_guest_t *guest;
	uint64_t vmid;

	vmid = get_current_vmid();
	guest = get_guest(vmid);
	if (!guest)
		return -ENOENT;

	guest->state = state;
	return 0;
}

guest_state_t get_guest_state(uint64_t vmid)
{
	kvm_guest_t *guest;

	guest = get_guest(vmid);
	if (!guest)
		return guest_invalid;

	return guest->state;
}

int init_guest(void *kvm)
{
	kvm_guest_t *guest = NULL;
	uint64_t *pgd;
	int i;

	if (!kvm)
		return -EINVAL;

	kvm = kern_hyp_va(kvm);
	for (i = 0; i < MAX_GUESTS; i++) {
		if (guests[i].kvm == kvm) {
			guest = &guests[i];
			break;
		}
	}

	if (!guest) {
		guest = get_free_guest();
		if (!guest)
			return -ENOSPC;

		guest->s2_pgd = alloc_table(guest->vmid);
		if (!guest->s2_pgd) {
			free_guest(guest);
			return -ENOMEM;
		}
	}

	/*
	 * FIXME: the real thing to do here is to protect the kernel
	 * writable shared blobs, like the kvm.
	 */
	pgd = KVM_GET_PGD_PTR(kvm);
	*pgd = (uint64_t)guest->s2_pgd;
	guest->kvm = kvm;
	guest->table_levels = GUEST_TABLE_LEVELS;

	/* Save the current VM process stage1 PGD */
	guest->s1_pgd = (struct ptable *)read_reg(TTBR0_EL1);
#if DEBUGDUMP
	print_mappings(0, STAGE2, SZ_1G, SZ_1G*5);
#endif
	return 0;
}

/* NOTE; KVM is hyp addr */

kvm_guest_t *get_guest_by_kvm(void *kvm)
{
	kvm_guest_t *guest = NULL;
	int i, rc = 0;

retry:
	for (i = 0; i < MAX_GUESTS; i++) {
		if (guests[i].kvm == kvm) {
			guest = &guests[i];
			break;
		}
	}
	if (!guest) {
		i = init_guest(kvm);
		if (i)
			return NULL;
		rc += 1;
		if (rc < 2)
			goto retry;
	}
	return guest;
}

kvm_guest_t *get_guest_by_s1pgd(struct ptable *pgd)
{
	kvm_guest_t *guest = NULL;
	int i;

	for (i = 0; i < MAX_GUESTS; i++) {
		if (guests[i].s1_pgd == pgd) {
			guest = &guests[i];
			break;
		}
	}
	return guest;
}

kvm_guest_t *get_guest_by_s2pgd(struct ptable *pgd)
{
	kvm_guest_t *guest = NULL;
	int i;

	for (i = 0; i < MAX_GUESTS; i++) {
		if (guests[i].s2_pgd == pgd) {
			guest = &guests[i];
			break;
		}
	}
	return guest;
}

int guest_map_range(kvm_guest_t *guest, uint64_t vaddr, uint64_t paddr,
		    uint64_t len, uint64_t prot, uint64_t type)
{
	uint64_t page_vaddr, page_paddr, taddr;
	int res;

	if (!guest || !vaddr || !paddr || (len % PAGE_SIZE)) {
		res = -EINVAL;
		goto out_error;
	}
	/*
	 * Verify that the range is within the guest boundary.
	 */
	res = is_range_valid(vaddr, len, guest->slots);
	if (!res) {
		ERROR("vmid %x attempting to map invalid range 0x%lx - 0x%lx\n",
		      guest->vmid, vaddr, vaddr + len);
		res = -EINVAL;
		goto out_error;
	}
	/*
	 * Do we know about this area?
	 */
	page_vaddr = vaddr;
	page_paddr = paddr;
	while (page_vaddr < (vaddr + len)) {
		/*
		 * If it's already mapped, bail out. This is not secure,
		 * so for all remaps force a unmap first so that we can
		 * measure the existing content.
		 */
		taddr = pt_walk(guest->s2_pgd, page_vaddr, NULL,
				GUEST_TABLE_LEVELS);
		if ((taddr != ~0UL) && (taddr != page_paddr)) {
			ERROR("vmid %x 0x%lx already mapped: 0x%lx != 0x%lx\n",
			      guest->vmid, (uint64_t)page_vaddr,
			      taddr, page_paddr);
			res = -EPERM;
			break;
		}
		/*
		 * If it wasn't mapped and we are mapping it back,
		 * verify that the content is still the same.
		 */
		res = verify_range(guest, page_vaddr, page_paddr, PAGE_SIZE);
		if (res == -EINVAL)
			goto out_error;

		page_vaddr += PAGE_SIZE;
		page_paddr += PAGE_SIZE;
	}
	/*
	 * Request the MMU to tell us if this was touched, if it can.
	 */
	bit_set(prot, DBM_BIT);

	res = mmap_range(guest->s2_pgd, STAGE2, vaddr, paddr, len, prot, type);
	if (!res)
		res = blind_host(vaddr, paddr, len);

out_error:
	return res;
}

int guest_unmap_range(kvm_guest_t *guest, uint64_t vaddr, uint64_t len,
		      bool measure)
{
	uint64_t paddr, map_addr;
	uint64_t *pte;
	int res, pc = 0;

	if (!guest || !vaddr || (len % PAGE_SIZE)) {
		res = 0xF0F0;
		goto out_error;
	}

	map_addr = vaddr;
	while (map_addr < (vaddr + len)) {
		paddr = pt_walk(guest->s2_pgd, map_addr, &pte,
				GUEST_TABLE_LEVELS);
		if (paddr == ~0UL)
			goto do_loop;
		/*
		 * If the vm dirty data is never allowed to leak, don't set
		 * up a swap. Normal clean / file backed page reclaim will
		 * work and the dirty data can't leak to the swapfile.
		 *
		 * If you have a swap, things will still work to the extent
		 * that we verify that the data comes back from the swap
		 * intact.
		 */
		if (measure) {
			/*
			 * This is a mmu notifier chain call and the blob may
			 * get swapped out or freed. Take a measurement to
			 * make sure it does not change while out.
			 */
			res = add_range_info(guest, vaddr, paddr, PAGE_SIZE);
			if (res)
				HYP_ABORT();
		}
		/*
		 * Do not leak guest data
		 */
		memset((void *)paddr, 0, PAGE_SIZE);
		/*
		 * Detach the page from the guest
		 */
		res = unmap_range(guest->s2_pgd, STAGE2, vaddr, PAGE_SIZE);
		if (res)
			HYP_ABORT();
		/*
		 * Give it back to the host
		 */
		res = restore_blinded_range(paddr, paddr, PAGE_SIZE);
		if (res)
			HYP_ABORT();

		pc += 1;
do_loop:
		map_addr += PAGE_SIZE;
		if (pc == 0xFFFF)
			HYP_ABORT();
	}

out_error:
	/*
	 * If it ended with an error, append info on how many
	 * pages were actually unmapped.
	 */
	if (res)
		res |= (pc << 16);

	return res;

}

#ifdef HOSTBLINDING

int restore_blinded_range(uint64_t vaddr, uint64_t paddr, uint64_t len)
{
	kvm_guest_t *host;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	return mmap_range(host->s2_pgd, STAGE2, vaddr, paddr,
			  len, PAGE_HYP_RWX, NORMAL_MEMORY);
}

int restore_host_mappings(kvm_guest_t *guest)
{
	uint64_t slot_start, slot_end, size;
	uint64_t slot_addr;
	kvm_guest_t *host;
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
			slot_addr = pt_walk(guest->s2_pgd, slot_end, NULL, 4);
			if (slot_addr == ~0UL) {
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
					 PAGE_SIZE, PAGE_HYP_RWX, NORMAL_MEMORY);
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

	LOG("map back v:0x%lx -> p:0x%lx\n", far_el2, ipa);

	ipa = ipa & PAGE_MASK;

	/* 1:1 mapping - TODO the parameters from platform map */
	if (mmap_range(host->s2_pgd, STAGE2, ipa, ipa,
		       PAGE_SIZE, ((SH_NO<<8)|PAGE_HYP_RWX), (S2_OWB|S2_IWB)))
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

int free_guest(void *kvm)
{
	kvm_guest_t *guest = NULL;
	int i, res;

	if (!kvm)
		return -EINVAL;

	kvm = kern_hyp_va(kvm);
	for (i = 0; i < MAX_GUESTS; i++) {
		if (guests[i].kvm == kvm) {
			guest = &guests[i];
			break;
		}
	}
	if (!guest)
		return 0;

	if (guest->vmid) {
		res = restore_host_mappings(guest);
		if (res)
			return res;

		free_guest_tables(guest->vmid);
		free_table(guest->s2_pgd);
	}

	memset (guest, 0, sizeof(*guest));
#if DEBUGDUMP
	print_mappings(0, STAGE2, SZ_1G, SZ_1G*5);
#endif
	return 0;
}

int update_memslot(void *kvm, kvm_memslot *slot,
		   kvm_userspace_memory_region *reg)
{
	kvm_guest_t *guest;
	uint64_t addr, size;

	if (!kvm || !slot || !reg)
		return -EINVAL;

	kvm = kern_hyp_va(kvm);
	slot = kern_hyp_va(slot);
	reg = kern_hyp_va(reg);

	guest = get_guest_by_kvm(kvm);
	if (!guest)
		return 0;

	if (guest->sn > KVM_MEM_SLOTS_NUM)
		return -EINVAL;

	addr = fn_to_addr(slot->base_gfn);
	size = slot->npages * PAGE_SIZE;

	/* Check dupes */
	if (is_range_valid(addr, size, &guest->slots[0]))
		return 0;

	memcpy(&guest->slots[guest->sn].region, reg, sizeof(*reg));
	memcpy(&guest->slots[guest->sn].slot, slot, sizeof(*slot));

	LOG("guest 0x%lx slot 0x%lx - 0x%lx\n", kvm, addr, addr + size);
	guest->sn++;

	return 0;
}

int guest_user_copy(uint64_t dest, uint64_t src, uint64_t count)
{
	uint64_t ttbr0_el1 = (read_reg(TTBR0_EL1) & TTBR_BADDR_MASK);
	uint64_t ttbr1_el1 = (read_reg(TTBR1_EL1) & TTBR_BADDR_MASK);
	uint64_t usr_addr, dest_pgd, src_pgd;
	kvm_guest_t *guest = NULL;

	/* Check if we have such guest */
	guest = get_guest_by_s1pgd((struct ptable *)ttbr0_el1);
	if (guest == NULL)
		return -ENOENT;

	if (guest->vmid == HOST_VMID)
		return -ENOENT;

	/*
	 * Set the guest user address and page tables to use.
	 * ttbr1_el1 contain the host kernel view of the memory.
	 * ttbr0_el1 contain the guest user space view of the memory.
	 */
	if ((dest & KERNEL_MAP)) {
		usr_addr = src;
		dest_pgd = ttbr1_el1;
		src_pgd = ttbr0_el1;
	} else {
		usr_addr = dest;
		dest_pgd = ttbr0_el1;
		src_pgd = ttbr1_el1;
	}

	/* Check that the guest address is within guest boundaries */
	if (!is_range_valid_uaddr(usr_addr, count, &guest->slots[0]))
		return -EINVAL;

	return user_copy(dest, src, count, dest_pgd, src_pgd);
}

static int compfunc(const void *v1, const void *v2)
{
	kvm_page_data *val1 = (kvm_page_data *)v1;
	kvm_page_data *val2 = (kvm_page_data *)v2;

	return (val1->phys_addr - val2->phys_addr);
}

kvm_page_data *get_range_info(kvm_guest_t *guest, uint64_t ipa)
{
	kvm_page_data key, *res;

	if (!guest)
		return NULL;

	key.phys_addr = ipa;
	res = bsearch(&key, guest->hyp_page_data, guest->pd_index,
		      sizeof(key), compfunc);

	return res;
}

int add_range_info(kvm_guest_t *guest, uint64_t ipa, uint64_t addr,
		   uint64_t len)
{
	kvm_page_data *res;
	int ret;
	bool s = false;

	if (!guest || !ipa || !addr || !len || len % PAGE_SIZE)
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
	res->vmid = guest->vmid;
	res->len = len;
	ret = calc_hash(res->sha256, (void *)addr, len);
	if (ret) {
		memset(res->sha256, 0, 32);
		res->vmid = 0;
	}
	if (s)
		qsort(guest->hyp_page_data, guest->pd_index, sizeof(kvm_page_data),
		      compfunc);

	return ret;
}

void free_range_info(kvm_guest_t *guest, uint64_t ipa)
{
	kvm_page_data *res;

	res = get_range_info(guest, ipa);
	if (!res)
		return;

	res->vmid = 0;
	memset(res->sha256, 0, 32);
}

int verify_range(kvm_guest_t *guest, uint64_t ipa, uint64_t addr, uint64_t len)
{
	kvm_page_data *res;
	uint8_t sha256[32];
	int ret;

	res = get_range_info(guest, ipa);
	if (!res)
		return -ENOENT;

	if (res->vmid != guest->vmid)
		return -EFAULT;

	ret = calc_hash(sha256, (void *)addr, len);
	if (ret)
		return -EFAULT;

	ret = memcmp(sha256, res->sha256, 32);
	if (ret != 0)
		return -EINVAL;

	return 0;
}
