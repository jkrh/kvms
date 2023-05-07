/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARMTRANS_H__
#define __ARMTRANS_H__

#include <stdint.h>
#include <stdbool.h>

#include "guest.h"
#include "arm-tabledefs.h"

struct ptable
{
	uint64_t entries[PT_SIZE_WORDS];
};

#define EL2_STAGE1	0
#define STAGE1		1
#define STAGE2		2
#define STAGEA		3
#define PATRACK_STAGE1	4

/*
 * Stage 1 MAIR_EL2 slot. Standard linux allocation on
 * virt, platform specific otherwise.
 */
#define DEVICE_STRONGORDER	(PLAT_DEVICE_STRONGORDER << ATTR_INDX_SHIFT)
#define DEVICE_ORDER		(PLAT_DEVICE_ORDER << ATTR_INDX_SHIFT)
#define DEVICE_GRE		(PLAT_DEVICE_GRE << ATTR_INDX_SHIFT)
#define NORMAL_NOCACHE		(PLAT_NORMAL_NOCACHE << ATTR_INDX_SHIFT)
#define NORMAL_WBACK_P		(PLAT_NORMAL_WBACK_P << ATTR_INDX_SHIFT)
#define NORMAL_WT_P		(PLAT_NORMAL_WT_P << ATTR_INDX_SHIFT)
#define NORMAL_MEMORY NORMAL_WBACK_P
#define DEVICE_MEMORY DEVICE_ORDER
#define INVALID_MEMORY		(1 << 6)
#define KERNEL_MATTR		(1 << 7)
#define KEEP_MATTR		(1 << 8)

/* Stage 2 normal memory attributes */
#define S2_NORMAL_MEMORY	(S2_OWB | S2_IWB)

/*
 * Default shareability settings.
 */
#ifndef EL1S2_SH
#define EL1S2_SH (SH_INN << SH_SHIFT)
#endif
#ifndef EL2S1_SH
#define EL2S1_SH (SH_INN << SH_SHIFT)
#endif

/**
 * Enable mmu for the current host VM. machine_init() must have been
 * invoked first to populate the host page tables.
 */
void enable_mmu(void);

/**
 * Generic page table walk function. Resolve a physical address or IPA
 * of a given virtual address for given guest.
 *
 * @param guest guest to walk
 * @param stage stage of the walk (STAGE1, STAGE2, STAGEA)
 * @param vaddr virtual address to resolve
 * @param ptep uint64_t pointer or NULL
 * @return physical address and page permissions in **ptep, ~0UL on error
 */
uint64_t pt_walk(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
		 uint64_t **ptep);

/**
 * Generic page table walk for the EL2 mode.
 *
 * @param vaddr virtual address to resolve
 * @param ptep uint64_t pointer or NULL
 * @return physical address and page permissions in **ptep, ~0UL on error
 */
uint64_t pt_walk_el2(uint64_t vaddr, uint64_t **ptep);

/**
 * Prevents the calling kernel from ever changing its internal memory
 * area EL1 mappings for a given area. Primary use case is to make sure
 * the rodata stays rodata.
 *
 * BIG FAT WARNING: THIS FUNCTION IS VERY DIFFICULT TO USE AND PROBABLY
 * REQUIRES RE-ARRANGING THE KERNEL IMAGE CONTENTS. UNLESS YOU REALLY
 * KNOW WHAT YOU ARE DOING IT PROBABLY LOCKS SOMETHING UNEXPECTED.
 * In minimum this will lock 512 * 4k section described by a single
 * page table that might clash with something RW. One level up and we
 * are already locking 1GB blocks (512 * 2MB).
 *
 * That being said, note that the kernel is lifted above page offset
 * and scattered all over the place over a pretty large area. For
 * any successful use the locked regions have to align on the block
 * boundary (2M - 1GB - 512GB) and be separated in the kernel such that
 * RW/RO data do not mix. You probably want to move the kernel rodata
 * into a block whose entire table chain can be locked.
 *
 * Note the requirement of 4k granule size and the fact that the code is
 * not entirely complete.
 *
 * @param vaddr kernel virtual address base
 * @param size size of the range
 * @param depth table depth to lock as bitmask (set bits 0..3)
 * @return zero on success or negative error code on failure
 */
int lock_host_kernel_area(uint64_t addr, size_t size, uint64_t depth);

/*
 * This is unlocked version of mmap/unmap functions
 * These should be locked with spin_lock/unlock(&guest->hvc_lock)
 *
 * Example:
 *    spin_lock(&guest->hvc_lock);
 *    mmap/unmap_range_unlocked(...);
 *    spin_unlock(&guest->hvc_lock);
 */
int mmap_range_unlocked(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
			uint64_t paddr, size_t length, uint64_t prot,
			uint64_t type);
int unmap_range_unlocked(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
			 size_t length);

/**
 * Generic stage-1 and -2 map function
 *
 * @param guest to map into.
 * @param stage EL2_STAGE1 or STAGE2
 * @param vaddr virtual address to map
 * @param paddr physical address to map to
 * @param length page aligned length of the mapping
 * @param prot memory protection attributes (see above)
 * @param type type of the memory. In case of KERNEL_MATTR
 *             the type is embedded in prot parameter.
 * @return zero or success or negative error code on failure
 */
int mmap_range(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
	       uint64_t paddr, size_t length, uint64_t prot, uint64_t type);

/**
 * Generic stage-1 and -2 unmap function
 *
 * @param guest to unmap from.
 * @param stage EL2_STAGE1 or STAGE2
 * @param vaddr virtual address to unmap
 * @param length page aligned length to unmap
 * @return zero or success or negative error code on failure
 */
int unmap_range(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
		size_t length);

/**
 * Verify if pte 'newattr' is a subset of 'oldattr' in terms of permissions
 *
 * @param newattr
 * @param oldattr
 * @return one if it is, zero otherwise
 */
int has_less_s2_perms(uint64_t newattr, uint64_t oldattr);

/**
 * Copy count bytes of memory from src to dest by using specified
 * address mappings.
 *
 * @param dest destination virtual address
 * @param src source virtual address
 * @param count amount of bytes to copy
 * @param dest_pgd destination mappings to use
 * @param src_pgd source mappings to use
 * @return zero if copy was done, negative error code otherwise
 */
int user_copy(uint64_t dest, uint64_t src, uint64_t count, uint64_t dest_pgd,
	      uint64_t src_pgd);


#endif // __ARMTRANS_H__
