/* SPDX-License-Identifier: GPL-2.0-only */

#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "platform_api.h"
#include "host_platform.h"
#include "hyplogs.h"
#include "helpers.h"
#include "mhelpers.h"
#include "guest.h"
#include "cache.h"
#include "hvccall.h"
#include "bits.h"
#include "tables.h"

typedef enum {
	PTE_FOUND = 0,
	PTE_NEXT_TBL,
	PTE_NOT_FOUND,
	PTE_INVALID
} tbl_search_t;

extern struct tdinfo_t tdinfo;

/* Static allocations for translation tables */
struct ptable guest_tables[TTBL_POOLS][STATIC_TTBL_NUM] ALIGN(PAGE_SIZE) SECTION("xlat_table");
kvm_guest_t *guest_table_user[TTBL_POOLS];

void table_init(void)
{
	kvm_guest_t *host;

	/* Clean up everything */
	if (_zeromem16(guest_tables, sizeof(guest_tables))) {
		ERROR("guest_tables not initialized, check alignment!\n");
		HYP_ABORT();
	}
	__flush_dcache_area((void *)guest_tables, sizeof(guest_tables));

	isb();

	host = get_guest(HOST_VMID);
	/* Init host side tables */
	if (platform_init_host_pgd(host))
		HYP_ABORT();

	LOG("HOST INFO: VMID %x, EL2 S1 PGD 0x%lx, EL1 S2 PGD 0x%lx\n",
	    HOST_VMID, (uint64_t)host->EL2S1_pgd, (uint64_t)host->EL1S2_pgd);
}

uint64_t table_oaddr(uint64_t tbl_entry)
{
	uint64_t tbl_addr = 0;

	if (bit_raised(tbl_entry, TABLE_TYPE_BIT))
		tbl_addr = tbl_entry & tdinfo.table_oa_mask;

	return tbl_addr;
}

void tdinfo_init(void)
{
	int granule_size;

	if (PLATFORM_VTCR_EL2 == 0)
		HYP_ABORT();

	granule_size = ((PLATFORM_VTCR_EL2 >> 14) & 3);
	switch (granule_size) {
	case GRANULE_SIZE_4KB:
		tdinfo.l1_blk_oa_mask = L1_BLK_OADDR_MASK_4KGRANULE;
		tdinfo.l2_blk_oa_mask = L2_BLK_OADDR_MASK_4KGRANULE;
		tdinfo.l1_blk_offt_mask = L1_POFFT_MASK_4KGRANULE;
		tdinfo.l2_blk_offt_mask = L2_POFFT_MASK_4KGRANULE;
		tdinfo.l1_blk_size = L1_POFFT_MASK_4KGRANULE + 1;
		tdinfo.l2_blk_size = L2_POFFT_MASK_4KGRANULE + 1;
		tdinfo.table_oa_mask = TABLE_OADDR_MASK_4KGRANULE;
		break;
	case GRANULE_SIZE_16KB:
	case GRANULE_SIZE_64KB:
	default:
		HYP_ABORT();
	break;
	}
}

static int alloc_static_ttbl_chunk(kvm_guest_t *guest)
{
	int i, c;
	guest_memchunk_t chunk;

	for (i = 0; i < TTBL_POOLS; i++) {
		if (!guest_table_user[i])
			break;
	}

	if (i >= TTBL_POOLS)
		return -ENOSPC;

	chunk.start = (uint64_t)guest_tables[i];
	chunk.size  = (STATIC_TTBL_NUM * sizeof(struct ptable));
	chunk.type = GUEST_MEMCHUNK_TTBL;

	c = __guest_memchunk_add(guest, &chunk);
	if (c >= 0)
		guest_table_user[i] = guest;

	return c;
}

static int free_static_ttbl_chunk(struct tablepool *tpool)
{
	guest_memchunk_t chunk;
	int i, err;

	chunk.start = tpool->guest->mempool[tpool->currentchunk].start;

	for (i = 0; i < TTBL_POOLS; i++) {
		if ((uint64_t)guest_tables[i] == chunk.start)
			break;
	}

	if (i >= TTBL_POOLS)
		return -ENOENT;

	chunk.size = tpool->guest->mempool[tpool->currentchunk].size;
	chunk.type = tpool->guest->mempool[tpool->currentchunk].type;

	if (guest_table_user[i] != tpool->guest) {
		ERROR("%s guest mismatch!\n", __func__);
		HYP_ABORT();
	}

	err = __guest_memchunk_remove(tpool->guest, &chunk);
	if (err)
		ERROR("%s, unable to remove %lx, err %d\n",
		      __func__, chunk.start, err);

	guest_table_user[i] = 0;

	return 0;
}

int get_tablepool(struct tablepool *tpool, uint64_t c)
{
	int i, poolsize, pool_start;

	if (c >= GUEST_MEMCHUNKS_MAX)
		return -EINVAL;

	if (tpool->guest->mempool[c].type != GUEST_MEMCHUNK_TTBL)
		return -EINVAL;

	i = tpool->firstchunk;
	pool_start = 0;
	while (i < GUEST_MEMCHUNKS_MAX) {
		if (i == c)
			break;
		poolsize = tpool->guest->mempool[i].size;
		pool_start += poolsize / sizeof(struct ptable);
		i = tpool->guest->mempool[i].next;
	}

	if (i >= GUEST_MEMCHUNKS_MAX)
		return -ENOENT;

	tpool->pool = (struct ptable *)tpool->guest->mempool[i].start;
	tpool->num_tables = tpool->guest->mempool[i].size / sizeof(struct ptable);
	tpool->used = &tpool->props[pool_start];
	tpool->currentchunk = i;
	tpool->hint = 0;

	return 0;
}

struct ptable *alloc_tablepool(struct tablepool *tpool)
{
	int c, i, poolsize, pool_start;

	tpool->pool = NULL;


	c = guest_memchunk_alloc(tpool->guest, PAGE_SIZE,
				GUEST_MEMCHUNK_TTBL);

	if (c < 0)
		c = alloc_static_ttbl_chunk(tpool->guest);

	if (c < 0)
		return NULL;

	if (tpool->currentchunk < GUEST_MEMCHUNKS_MAX) {
		tpool->guest->mempool[c].previous = tpool->currentchunk;
		tpool->guest->mempool[tpool->currentchunk].next = c;
	} else {
		tpool->guest->mempool[c].previous = GUEST_MEMCHUNKS_MAX;
		tpool->firstchunk = c;
	}

	tpool->currentchunk = c;

	tpool->pool = (struct ptable *)tpool->guest->mempool[c].start;
	tpool->num_tables = tpool->guest->mempool[c].size / sizeof(struct ptable);

	/* Table accounting */
	i = tpool->firstchunk;
	pool_start = 0;
	while (tpool->guest->mempool[i].next < GUEST_MEMCHUNKS_MAX) {
		poolsize = tpool->guest->mempool[i].size;
		pool_start += poolsize / sizeof(struct ptable);
		i = tpool->guest->mempool[i].next;
	}

	tpool->used = &tpool->props[pool_start];
	tpool->hint = 0;

	if (tpool->used[tpool->hint]) {
		ERROR("%s table accounting error!\n", __func__);
		return NULL;
	}

	return tpool->pool;
}

int tablepool_get_free_idx(struct tablepool *tpool, bool *new_pool)
{
	int i;

	if (new_pool != NULL)
		*new_pool = false;

	if (!tpool->used[tpool->hint])
		i = tpool->hint;
	else {
		for (i = 0; i < tpool->num_tables; i++) {
			if (!tpool->used[i])
				break;
		}
		if (i >= tpool->num_tables) {
			if (alloc_tablepool(tpool) == NULL)
				return -ENOSPC;
			i = 0;
			if (new_pool != NULL)
				*new_pool = true;
		}
	}

	return i;
}

struct ptable *alloc_table(struct tablepool *tpool)
{
	struct ptable *table;
	int i;

	table = NULL;
	i = tablepool_get_free_idx(tpool, NULL);

	if (i >= 0) {
		table = &tpool->pool[i];
		/* Set the table as used */
		tpool->used[i] = 1;

		if ((i + 1) < tpool->num_tables)
			tpool->hint = i + 1;
	}

	return table;
}

static uint64_t *next_pte_from_tbl(uint64_t *table, uint64_t *tblpos)
{
	uint64_t desci;
	uint64_t *pte = NULL;

	for (desci = *tblpos; desci < PT_SIZE_WORDS; desci++) {
		if (table[desci] == 0)
			continue;

		pte = &table[desci];
		break;
	}

	*tblpos = desci;

	return pte;
}

static tbl_search_t pte_from_tbl_by_oaddr(uint64_t *tbl, uint64_t *tblpos,
				   uint64_t **pte, uint64_t oaddr)
{
	tbl_search_t res = PTE_NOT_FOUND;
	uint64_t *tpte = NULL;
	uint64_t toaddr, desci;

	for (desci = *tblpos; desci < PT_SIZE_WORDS; desci++) {
		tpte = next_pte_from_tbl(tbl, &desci);
		if (desci >= PT_SIZE_WORDS)
			break;

		if (bit_raised(*tpte, VALID_TABLE_BIT)) {
			toaddr = table_oaddr(*tpte);
			if (toaddr == oaddr) {
				*pte = tpte;
				res = PTE_FOUND;
				break;
			}
			if (bit_raised(*tpte, TABLE_TYPE_BIT)) {
				*pte = (uint64_t *)toaddr;
				res = PTE_NEXT_TBL;
				break;
			}
		}
	}

	*tblpos = desci;

	return res;
}

static uint64_t *pte_from_pgd_by_oaddr(struct ptable *pgd, uint64_t oaddr,
				uint64_t levels, uint64_t lastlevel)
{
	tbl_search_t res = PTE_INVALID;
	uint64_t desci[MAX_TABLE_LEVELS] = {0};
	uint64_t *pte[MAX_TABLE_LEVELS] = {NULL};
	uint64_t firstlevel, searchlevel;
	uint64_t *tpte = NULL;

	if (levels > MAX_TABLE_LEVELS || lastlevel >= 3)
		HYP_ABORT();

	firstlevel = MAX_TABLE_LEVELS - levels;
	pte[firstlevel] = pgd->entries;
	searchlevel = firstlevel;

	while (desci[firstlevel] < PT_SIZE_WORDS) {
		res = pte_from_tbl_by_oaddr(pte[searchlevel],
					    &desci[searchlevel], &tpte, oaddr);

		switch (res) {
		case PTE_NEXT_TBL:
			/*
			 * We found a table entry from current
			 * search level. Dive into the next level
			 * pointed by the table entry if we are
			 * required to do so by the specified
			 * lastlevel.
			 */
			desci[searchlevel]++;
			if (searchlevel < lastlevel) {
				searchlevel += 1;
				pte[searchlevel] = tpte;
				desci[searchlevel] = 0;
			}
			break;
		case PTE_NOT_FOUND:
			/*
			 * There was no more entries in the current
			 * searchlevel. Go back up one level if we
			 * are not already in the highest required
			 * level.
			 */
			if (searchlevel > firstlevel)
				searchlevel -= 1;
			break;
		case PTE_FOUND:
			/*
			 * We found the output address we were searching
			 * for. Return the page table entry pointing to it.
			 */
			return tpte;
		default:
			HYP_ABORT();
			break;
		}
	}

	return NULL;
}

static int clean_parentpgd(struct tablepool *tpool, struct ptable *ppgd)
{
	int res = -ENOENT;
	uint64_t table;
	struct ptable *tableptr;
	uint64_t *pte;
	uint64_t desci;

	for (table = 0; table < tpool->num_tables; table++) {
		tableptr = &tpool->pool[table];
		desci = 0;
		pte = next_pte_from_tbl(tableptr->entries, &desci);
		if (pte == NULL)
			continue;
		/*
		 * There was entry found from table. Check if this table
		 * pointer is referenced by the tables in PGD hierarchy.
		 * Remove the reference if found.
		 */
		pte = pte_from_pgd_by_oaddr(ppgd, (uint64_t)tableptr,
						TABLE_LEVELS, 2);
		if (pte != NULL) {
			LOG("%s cleaned 0x%lx\n", __func__, *pte);
			*pte = 0;
		}
		memset(tableptr, 0, sizeof(struct ptable));
	}

	return res;
}

struct ptable *alloc_pgd(kvm_guest_t *guest, struct tablepool *tpool)
{
	struct ptable *pgd, *check;

	check = NULL;
	tpool->guest = guest;
	pgd = alloc_tablepool(tpool);
	if (pgd != NULL)
		check = alloc_table(tpool);

	if (pgd != check) {
		ERROR("%s invalid pgd!\n", __func__);
		return NULL;
	}

	return pgd;
}

int free_pgd(struct tablepool *tpool, struct ptable *pgd_base)
{
	guest_memchunk_t *mempool;
	int c, p;

	if (!tpool->guest)
		return -ENOENT;

	mempool = tpool->guest->mempool;
	c = tpool->firstchunk;
	while (mempool[c].next < GUEST_MEMCHUNKS_MAX)
		c = mempool[c].next;

	while (c < GUEST_MEMCHUNKS_MAX) {
		if (get_tablepool(tpool, c))
			break;
		if (pgd_base != NULL)
			clean_parentpgd(tpool, pgd_base);

		memset(tpool->pool, 0, tpool->num_tables * sizeof(struct ptable));
		memset(tpool->used, 0, tpool->num_tables);
		p = c;
		c = mempool[p].previous;
		mempool[p].type = GUEST_MEMCHUNK_FREE;
		mempool[p].next = GUEST_MEMCHUNKS_MAX;
		mempool[p].previous = GUEST_MEMCHUNKS_MAX;
		/* If it happens to be allocated from static memory */
		free_static_ttbl_chunk(tpool);
	}

	if (tpool == &tpool->guest->s1_tablepool) {
		dsb();
		tlbialle2is();
		dsb();
		isb();
	}

	if (tpool == &tpool->guest->s2_tablepool) {
		if (tpool->guest->vmid != HOST_VMID) {
			load_guest_s2(tpool->guest->vmid);
			isb();
		}
		dsb();
		tlbivmalls12e1is();
		dsb();
		isb();
		if (tpool->guest->vmid != HOST_VMID) {
			load_host_s2();
			isb();
		}
	}

	memset(tpool, 0, sizeof(struct tablepool));

	tpool->firstchunk = GUEST_MEMCHUNKS_MAX;
	tpool->currentchunk = GUEST_MEMCHUNKS_MAX;

	return 0;
}

int free_table(struct tablepool *tpool, struct ptable *table)
{
	int res = -ENOENT, i, c;

	c = tpool->firstchunk;
	do {
		if (get_tablepool(tpool, c))
			break;
		for (i = 0; i < tpool->num_tables; i++) {
			if (table == &tpool->pool[i]) {
				memset(&tpool->pool[i], 0, sizeof(struct ptable));
				tpool->used[i] = 0x0;
				res = 0;
			}
		}
		c = tpool->guest->mempool[c].next;
	} while (c < GUEST_MEMCHUNKS_MAX);

	return res;
}
