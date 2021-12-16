/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ARMTRANS_H__
#define __ARMTRANS_H__

#include <stdint.h>
#include <stdbool.h>

#include "guest.h"

#define MAX_TABLE_LEVELS	4

#define PT_SIZE_WORDS   512

struct ptable
{
	uint64_t entries[PT_SIZE_WORDS];
};

/*
 * Stage-1 S2AP
 *    EL1        EL0
 * 00 Read/write None
 * 01 Read/write Read/write
 * 10 Read-only  None
 * 11 Read-only  Read-only
 *
 * Stage-2 S2AP
 * 00 None
 * 01 Read-only
 * 10 Write-only
 * 11 Read/write
 */

#define PROT_MASK_STAGE1	0x600000000003E0
#define PROT_MASK_STAGE2	0x6A0000000003C0
#define TYPE_MASK_STAGE1	0x1C
#define TYPE_MASK_STAGE2	0x3C
#define ATTR_INDX_SHIFT		2

#define VADDR_MASK		0xFFFFFFFFFFFFUL
#define PAGE_SHARED		0x40000000000040
#define PAGE_SHARED_EXEC	0x00000000000040
#define ATTR_MASK		0xFFFC0000000003FCUL

/*
 * FIXME: we need more human readable permission bits.
 */

/* Stage 1 */
#define S1_PXN_SHIFT		53
#define S1_PXN			(1UL << S1_PXN_SHIFT)

#define S1_UXN_SHIFT		54
#define S1_UXN			(1UL << S1_UXN_SHIFT)

#define S1_AP_SHIFT		6
#define S1_AP_MASK		(0x3UL << S1_AP_SHIFT)

#define S1_AP_RW_N		0UL
#define S1_AP_RW_RW		(1UL << S1_AP_SHIFT)
#define S1_AP_RO_N		(2UL << S1_AP_SHIFT)
#define S1_AP_RO_RO		(3UL << S1_AP_SHIFT)

#define PAGE_KERNEL_RW		S1_UXN              //0x40000000000000
#define PAGE_KERNEL_RWX		0x00000000000000
#define PAGE_KERNEL_RO		(S1_UXN | S1_AP_RO_N) //0x40000000000080
#define PAGE_KERNEL_EXEC	S1_AP_RO_N          //0x00000000000080
/* Stage 2 */
#define S2_XN_SHIFT		53
#define S2_XN_MASK		(0x3UL << S2_XN_SHIFT)
#define S2_EXEC_EL1EL0		(0x0UL << S2_XN_SHIFT)
#define S2_EXEC_EL0		(0x1UL << S2_XN_SHIFT)
#define S2_EXEC_NONE		(0x2UL << S2_XN_SHIFT)
#define S2_EXEC_EL1		(0x3UL << S2_XN_SHIFT)

#define S2AP_SHIFT		6
#define S2AP_MASK		(0x3UL << S2AP_SHIFT)
#define S2AP_NONE		(0 << S2AP_SHIFT)
#define S2AP_READ		(1UL << S2AP_SHIFT)
#define S2AP_WRITE		(2UL << S2AP_SHIFT)
#define S2AP_RW			(3UL << S2AP_SHIFT)


#define S2_MEM_ATTR_SHIFT	2
#define S2_MEM_ATTR_MASK	(0x0fUL << S2_MEM_ATTR_SHIFT)

#define S2_MEMTYPE_DEVICE	0

#define PAGE_HYP_RW		(S2_EXEC_NONE | S2AP_RW)     //0x400000000000c0
#define PAGE_HYP_RWX		(S2_EXEC_EL1EL0 | S2AP_RW)   //0x000000000000c0
#define PAGE_HYP_RO		(S2_EXEC_NONE | S2AP_READ)   //0x40000000000040
#define PAGE_HYP_EXEC		(S2_EXEC_EL1EL0 | S2AP_READ) //0x00000000000040

#define STAGE1 0
#define STAGE2 1
#define STAGEA 3

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

/* Shareability SH [9:8], Stage 1 and 2 */
#define SH_SHIFT		0x8
#define SH_NO			0x0
#define SH_OUT			0x2
#define SH_INN			0x3

/* Stage 2 MemAttr[3:2] */
#define S2_MEM_ATTR_SHIFT	2
#define S2_MEM_TYPE_SHIFT	(S2_MEM_ATTR_SHIFT + 2)
#define S2_MEM_TYPE_MASK	(0x3 << S2_MEM_TYPE_SHIFT)
#define S2_DEVICE		(0x0 << S2_MEM_TYPE_SHIFT)
#define S2_ONONE		(0x1 << S2_MEM_TYPE_SHIFT)
#define S2_OWT			(0x2 << S2_MEM_TYPE_SHIFT)
#define S2_OWB			(0x3 << S2_MEM_TYPE_SHIFT)

/* Stage 2 MemAttr[1:0] Meaning when MemAttr[3:2] == 0b00 */
#define NGNRNE			(0x0 << S2_MEM_ATTR_SHIFT)
#define NGNRE			(0x1 << S2_MEM_ATTR_SHIFT)
#define NGRE			(0x2 << S2_MEM_ATTR_SHIFT)
#define GRE			(0x3 << S2_MEM_ATTR_SHIFT)

/* Stage 2 MemAttr[1:0] Meaning when MemAttr[3:2] != 0b00 */
/* Inner Non-cacheable */
#define S2_INONE		(0x1 << S2_MEM_ATTR_SHIFT)
/* Inner Write-Through Cacheable */
#define S2_IWT			(0x2 << S2_MEM_ATTR_SHIFT)
/* Inner Write-Back Cacheable */
#define S2_IWB			(0x3 << S2_MEM_ATTR_SHIFT)

/* Stage 2 normal memory attributes */
#define S2_NORMAL_MEMORY	(S2_OWB | S2_IWB)

/* Stage 2 device memory attributes */
#define S2_DEV_NGNRNE		(S2_DEVICE | NGNRNE)
#define S2_DEV_NGNRE		(S2_DEVICE | NGNRE)
#define S2_DEV_NGRE		(S2_DEVICE | NGRE)
#define S2_DEV_GRE		(S2_DEVICE | GRE)

#define TTBR_BADDR_MASK	0x0000FFFFFFFFFFFEUL
#define MAX_CONTIGUOUS	128

#define TCR_EL1_T0SZ_MASK	0x3FUL
#define TCR_EL1_T0SZ_SHIFT	0
#define TCR_EL1_T0SZ(x)		((x & TCR_EL1_T0SZ_MASK) >> TCR_EL1_T0SZ_SHIFT)

#define TCR_EL1_T1SZ_MASK	0x3F0000UL
#define TCR_EL1_T1SZ_SHIFT	16
#define TCR_EL1_T1SZ(x)		((x & TCR_EL1_T1SZ_MASK) >> TCR_EL1_T1SZ_SHIFT)

void tdinfo_init(void);

/**
 * Reset current host page tables.
 */
void table_init(void);

/**
 * Enable mmu for the current host VM. machine_init() must have been
 * invoked first to populate the host page tables.
 */
void enable_mmu(void);

/**
 * Allocate translation table area
 *
 * @param tpool tablepool structure to populate with information on the
 *		allocated area.
 * @return pointer to the start of table area or NULL if out of memory
 */
struct ptable *alloc_tablepool(struct tablepool *tpool);

/**
 * Get index to a free table entry within the currently active table pool
 *
 * If there is no space left in currently active pool a new pool will be
 * allocated and associated with the provided tablepool structure.
 *
 * @param tpool tablepool structure to get the index from
 * @param new_pool optional information on whether a new pool was allocated
 * @return index to the table pool or negative error code on failure
 */
int tablepool_get_free_idx(struct tablepool *tpool, bool *new_pool);

/**
 * Allocate a page table structure
 *
 * @param tpool to allocate from
 * @return page table pointer or NULL if out of memory
 */
struct ptable *alloc_table(struct tablepool *tpool);

/**
 * Alloc a page global directory
 *
 * @param guest for which the pgd is allocated for
 * @param tpool table pool to be associated with the pgd
 * @return pgd address on success or NULL on failure
 */
struct ptable *alloc_pgd(kvm_guest_t *guest, struct tablepool *tpool);

/**
 * Free a page global directory
 *
 * Free the memory area reserved for the PGD. Optionally (by setting the
 * pgd_base) also handle the case where the whole PGD memory is not freed
 * but a fragment of it. In this case the possible references to the area
 * being freed are cleaned from the remaining PGD. References needs to be
 * cleaned to avoid situation where the freed memory is allocated and used
 * by another SW entity leading to a corrupted translation table.
 *
 * @param tpool page table memory to be freed
 * @param pgd_base optional page global directory base address.
 *	  Set to NULL if the area pointer by tpool contain also the PGD base
 *	  address.
 *	  Set to PGD base address if the base address is not within the tpool
 *	  area.
 * @return zero on success or negative error code on failure
 */
int free_pgd(struct tablepool *tpool, struct ptable *pgd_base);

/**
 * Free a page table structure
 *
 * @param tpool table pool to free from
 * @param page table pointer to free
 * @return zero on success or negative error code on failure
 */
int free_table(struct tablepool *tpool, struct ptable *table);

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

/**
 * Generic stage-1 and -2 map function
 *
 * @param guest to map into.
 * @param stage STAGE1 or STAGE2
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
 * @param stage STAGE1 or STAGE2
 * @param vaddr virtual address to unmap
 * @param length page aligned length to unmap
 * @return zero or success or negative error code on failure
 */
int unmap_range(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
		size_t length);

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

/*
 * Internal use only below - keep out.
 */
int get_tablepool(struct tablepool *tpool, uint64_t c);


#endif // __ARMTRANS_H__
