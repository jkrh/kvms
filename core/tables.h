/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __TABLES_H__
#define __TABLES_H__

#include <stdint.h>
#include <stdbool.h>

#include "guest.h"
#include "host_defs.h"

#ifndef GUEST_MEMCHUNKS_MAX
#define GUEST_MEMCHUNKS_MAX 	256
#endif

#define DESCRIPTOR_SIZE		8
#define TABLE_SIZE_4KGRANULE	(512 * DESCRIPTOR_SIZE)

#define GUEST_MAX_PAGES		(GUEST_MEM_MAX / PAGE_SIZE)
#define GUEST_MAX_TABLESIZE	(GUEST_MAX_PAGES * DESCRIPTOR_SIZE)
#define GUEST_TABLES		(GUEST_MAX_TABLESIZE / TABLE_SIZE_4KGRANULE)

#define GUEST_MAX_TABLES	GUEST_TABLES
#define MAX_VM			(MAX_GUESTS + 1)
#define PGD_PER_VM		2
#define TTBL_POOLS		(MAX_VM * PGD_PER_VM)

/* Granule size constants as defined in VTCR_EL2.TG0 */
#define GRANULE_SIZE_4KB	0
#define GRANULE_SIZE_16KB	2
#define GRANULE_SIZE_64KB	1

#define L1_POFFT_MASK_4KGRANULE		0x000000003FFFFFFFUL
#define L2_POFFT_MASK_4KGRANULE		0x00000000001FFFFFUL
#define L1_BLK_OADDR_MASK_4KGRANULE	0x0000FFFFC0000000UL
#define L2_BLK_OADDR_MASK_4KGRANULE	0x0000FFFFFFE00000UL

#define TABLE_OADDR_MASK_4KGRANULE	0x0000FFFFFFFFF000UL
#define MAX_CONTIGUOUS_4KGRANULE	16

/*
 * Translation descriptor information.
 * This structure contain information
 * which changes when the translation
 * table granule size changes.
 */
typedef struct tdinfo_t
{
	uint64_t l1_blk_oa_mask;
	uint64_t l2_blk_oa_mask;
	uint64_t l1_blk_offt_mask;
	uint64_t l2_blk_offt_mask;
	uint64_t l1_blk_size;
	uint64_t l2_blk_size;
	uint64_t table_oa_mask;
} tdinfo_t ALIGN(16);

typedef enum {
	GUEST_MEMCHUNK_FREE = 0,
	GUEST_MEMCHUNK_TTBL,
	GUEST_MEMCHUNK_UNDEFINED,
} guest_memchunk_user_t;

typedef struct {
	uint64_t start;
	size_t size;
	guest_memchunk_user_t type;
	uint16_t next;
	uint16_t previous;
} guest_memchunk_t;

struct tablepool {
	struct kvm_guest *guest;
	struct ptable *pool;
	uint64_t num_tables;
	uint16_t firstchunk;
	uint16_t currentchunk;
	uint16_t hint;
	uint8_t *used;
	uint8_t props[GUEST_MAX_TABLES];
};

/**
 * Reset current host page tables.
 */
void table_init(void);

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
struct ptable *alloc_pgd(struct kvm_guest *guest, struct tablepool *tpool);

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

/*
 * Internal use only below - keep out.
 */
void tdinfo_init(void);

int get_tablepool(struct tablepool *tpool, uint64_t c);

uint64_t table_oaddr(uint64_t tbl_entry);

#endif
