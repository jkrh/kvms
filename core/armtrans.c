// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>

#include "platform_api.h"
#include "host_platform.h"
#include "hyplogs.h"
#include "armtrans.h"
#include "helpers.h"
#include "guest.h"
#include "bits.h"
#include "cache.h"
#include "hvccall.h"
#include "mhelpers.h"

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

#define DESCR_ATTR_MASK			0xFFFF00000001FFFFUL

#define MAX_PADDR			VADDR_MASK
#define MAX_VADDR			0xFFFFFFFFFFFFUL
#define TABLE_0_MASK			0xFF8000000000UL
#define TABLE_1_MASK			0x007FC0000000UL
#define TABLE_2_MASK			0x00003FE00000UL
#define TABLE_3_MASK			0x0000001FF000UL
#define PADDR_MASK			0x00FFFFFFF000UL
#define PAGE_OFF_MASK			0x000000000FFFUL

#define L0_SHIFT	(0xC + 0x9 + 0x9 + 0x9)
#define L1_SHIFT	(0xC + 0x9 + 0x9)
#define L2_SHIFT	(0xC + 0x9)
#define L3_SHIFT	(0xC)

#ifndef PLATFORM_VTCR_EL2
#define PLATFORM_VTCR_EL2 0x600000UL
#endif

typedef enum {
	PTE_FOUND = 0,
	PTE_NEXT_TBL,
	PTE_NOT_FOUND,
	PTE_INVALID
} tbl_search_t;

static uint64_t kmaidx2pmaidx[8];
static bool need_hyp_s1_init = true;

extern uint64_t hostflags;

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

typedef struct
{
	kvm_guest_t *guest;
	struct ptable *pgd;
	struct tablepool *tpool;
	uint64_t *contiguous[MAX_CONTIGUOUS];
	uint64_t *ptep;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t size;
	uint64_t prot;
	uint64_t type;
	uint64_t level;
	uint64_t stage;
} mblockinfo_t ALIGN(16);

typedef enum
{
	MAPPING_ACTIVE = 1,
	MAPPING_INACTIVE = 2,
} mmap_change_type;

struct entryinfo
{
	struct ptable *ttbl;
	uint64_t idx;
};

/* Static allocations for translation tables */
struct ptable guest_tables[TTBL_POOLS][STATIC_TTBL_NUM] ALIGN(PAGE_SIZE) SECTION("xlat_table");
kvm_guest_t *guest_table_user[TTBL_POOLS];

static uint8_t invalidate;
static struct tdinfo_t tdinfo;
static mblockinfo_t block ALIGN(16);

static void setup_hyp_stage1(void)
{
	uint64_t kmair, pmair;
	uint8_t kmairt[8], pmairt[8], i, j;

	/*
	 * Read in the kernel and platform memory attribute indirection
	 * setting.
	 */
	kmair = read_reg(MAIR_EL1);
	pmair = read_reg(MAIR_EL2);
	for (i = 0; i < 8; i++) {
		kmairt[i] = (kmair >> (8*i)) & 0xFF;
		pmairt[i] = (pmair >> (8*i)) & 0xFF;
	}

	/* Create the translation */
	for (i = 0; i < 8; i++) {
		for (j = 0; j < 8; j++) {
			if (kmairt[i] == pmairt[j]) {
				kmaidx2pmaidx[i] = (j << ATTR_INDX_SHIFT);
				break;
			}
		}
		if (j >= 8)
			HYP_ABORT();
	}

}

static uint8_t k2p_mattrindx(uint8_t attridx)
{
	if (need_hyp_s1_init) {
		setup_hyp_stage1();
		need_hyp_s1_init = false;
	}

	return kmaidx2pmaidx[(attridx >> ATTR_INDX_SHIFT)];
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

static uint64_t table_oaddr(uint64_t tbl_entry)
{
	uint64_t tbl_addr = 0;

	if (bit_raised(tbl_entry, TABLE_TYPE_BIT))
		tbl_addr = tbl_entry & tdinfo.table_oa_mask;

	return tbl_addr;
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

uint64_t __pt_walk(struct ptable *tbl, uint64_t vaddr, uint64_t **ptep,
		   uint64_t *levels, struct entryinfo *einfo)
{
	struct ptable *nl = tbl;
	uint64_t noff, boff, ret, addr = 0, lvl = 0;

	if (!levels || *levels >= 4) {
		/* Level 0 */
		noff = (vaddr & TABLE_0_MASK) >> L0_SHIFT;
		if (!bit_raised(nl->entries[noff], VALID_TABLE_BIT))
			return ~0UL;
		nl = (struct ptable *)table_oaddr(nl->entries[noff]);
		if (!nl)
			return ~0UL;
	}
	lvl++;

	if (!levels || *levels >= 3) {
		/* Level 1 */
		noff = (vaddr & TABLE_1_MASK) >> L1_SHIFT;
		if (!bit_raised(nl->entries[noff], VALID_TABLE_BIT))
			return ~0UL;
		if (!bit_raised(nl->entries[noff], TABLE_TYPE_BIT))
			goto block_type;
		nl = (struct ptable *)table_oaddr(nl->entries[noff]);
		if (!nl)
			return ~0UL;
	}
	lvl++;

	/* Level 2 */
	noff = (vaddr & TABLE_2_MASK) >> L2_SHIFT;
	if (!bit_raised(nl->entries[noff], VALID_TABLE_BIT))
		return ~0UL;
	if (!bit_raised(nl->entries[noff], TABLE_TYPE_BIT))
		goto block_type;
	nl = (struct ptable *)table_oaddr(nl->entries[noff]);
	if (!nl)
		return ~0UL;
	lvl++;

	/* Level 3 */
	noff = (vaddr & TABLE_3_MASK) >> L3_SHIFT;
	if (!bit_raised(nl->entries[noff], TABLE_TYPE_BIT))
		return ~0UL;
	addr = nl->entries[noff] & PADDR_MASK;
	lvl++;

block_type:
	switch (lvl) {
	case 1:
		addr = nl->entries[noff] & tdinfo.l1_blk_oa_mask;
		boff = vaddr & tdinfo.l1_blk_offt_mask;
		break;
	case 2:
		addr = nl->entries[noff] & tdinfo.l2_blk_oa_mask;
		boff = vaddr & tdinfo.l2_blk_offt_mask;
		break;
	default:
		addr = addr & ~PAGE_OFF_MASK;
		boff = vaddr & PAGE_OFF_MASK;
		break;
	}
	if (levels)
		*levels = lvl;

	ret = addr | boff;

	if (ptep)
		*ptep = &nl->entries[noff];

	if (einfo) {
		einfo->ttbl = nl;
		einfo->idx = noff;
	}

	return ret;
}

uint64_t pt_walk(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
		 uint64_t **ptep)
{
	kvm_guest_t *host;
	struct ptable *tbl;
	uint64_t addr, ipa, lvl;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	if (guest == host) {
		host->EL1S1_1_pgd = (struct ptable *)(read_reg(TTBR1_EL1) & TTBR_BADDR_MASK);
		host->EL1S1_0_pgd = (struct ptable *)(read_reg(TTBR0_EL1) & TTBR_BADDR_MASK);
	}

	switch (stage) {
	case STAGEA:
		ipa = pt_walk(guest, STAGE1, vaddr, 0);
		if (ipa == ~0UL) {
			addr = ipa;
			break;
		}
		addr = pt_walk(guest, STAGE2, ipa, 0);
		break;
	case STAGE2:
		lvl = guest->table_levels_s2;
		addr = __pt_walk(guest->EL1S2_pgd, vaddr, ptep, &lvl, NULL);
		break;
	case STAGE1:
		/*
		 * Kernel or userspace address? We don't track the userspace
		 * beyond the vm qemu, so we resolve against that.
		 */
		if (bit_raised(vaddr, 55))
			tbl = guest->EL1S1_1_pgd;
		else
			tbl = guest->EL1S1_0_pgd;

		lvl = guest->table_levels_s1;
		addr = __pt_walk(tbl, vaddr, ptep, &lvl, NULL);
		break;
	default:
		addr = ~0UL;
		break;
	}

	return addr;
}

uint64_t pt_walk_el2(uint64_t vaddr, uint64_t **ptep)
{
	kvm_guest_t *host;
	uint64_t lvl;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	lvl = host->table_levels_s2;
	return __pt_walk(host->EL2S1_pgd, vaddr, ptep, &lvl, NULL);
}

static int lock_kernel_page(kvm_guest_t *guest, uint64_t ipa)
{
	uint64_t phys;
	uint64_t *ptep;

	phys = pt_walk(guest, STAGE2, ipa, &ptep);
	if ((phys == ~0UL) || !*ptep) {
		ERROR("lock_kernel_page(): ipa %p without a map?\n", ipa);
		return -EINVAL;
	}
	*ptep &= ~(S2_XN_MASK | S2AP_MASK);
	*ptep |= PAGE_HYP_RO;

	dsbish();
	isb();
	tlbi_el1_ipa(ipa);
	dsbish();
	isb();

	LOG("Locked guest %u physical page at %p\n", guest->vmid, phys);
	return 0;
}

int lock_host_kernel_area(uint64_t vaddr, size_t size, uint64_t depth)
{
	uint64_t ipa, noff, end, levels, ovaddr = vaddr;
	kvm_guest_t *guest = NULL;
	struct ptable *nl;

	LOG("Area lock requested for kernel %p, size %lu bytes\n", vaddr, size);

	guest = get_guest(HOST_VMID);
	if (!guest)
		HYP_ABORT();

	/*
	 * Don't go changing anything that's not there.
	 */
	ipa = pt_walk(guest, STAGE2, vaddr, 0);
	if (ipa == ~0UL) {
		ERROR("Host kernel %p does not appear to be mapped\n", vaddr);
		return -EINVAL;
	}
	nl = guest->EL1S2_pgd;
	levels = guest->table_levels_s2;

	if (depth & 0x1)
		lock_kernel_page(guest, (uint64_t)nl);

	vaddr = ROUND_UP(vaddr, SZ_1M * 2);
	size -= ovaddr - vaddr;
	size = ROUND_DOWN(size, SZ_1M * 2);
	LOG("Rounding the requested lock area: %p/%p, size %lu bytes\n", vaddr,
	     ipa, size);

	end = vaddr + size;
	while (vaddr < end) {
		if (levels >= 4) {
			noff = (vaddr & TABLE_0_MASK) >> L0_SHIFT;
			if (!bit_raised(nl->entries[noff], VALID_TABLE_BIT))
				goto cont;
			nl = (struct ptable *)table_oaddr(nl->entries[noff]);
			if (!nl)
				goto cont;
			if (depth & 0x2)
				lock_kernel_page(guest, (uint64_t)nl);
		}

		if (levels >= 3) {
			noff = (vaddr & TABLE_1_MASK) >> L1_SHIFT;
			if (!bit_raised(nl->entries[noff], VALID_TABLE_BIT))
				goto cont;
			if (!bit_raised(nl->entries[noff], TABLE_TYPE_BIT))
				goto cont;
			nl = (struct ptable *)table_oaddr(nl->entries[noff]);
			if (!nl)
				goto cont;
			if (depth & 0x4)
				lock_kernel_page(guest, (uint64_t)nl);
		}

		noff = (vaddr & TABLE_2_MASK) >> L2_SHIFT;
		if (!bit_raised(nl->entries[noff], VALID_TABLE_BIT))
			goto cont;
		if (!bit_raised(nl->entries[noff], TABLE_TYPE_BIT))
			goto cont;
		nl = (struct ptable *)table_oaddr(nl->entries[noff]);
		if (!nl)
			goto cont;
		if (depth & 0x8)
			lock_kernel_page(guest, (uint64_t)nl);

cont:
		vaddr += 0x1000;
	}
	return 0;
}

/*
 * Return true if block mapping for the given virtual address is found
 * and block info is populated. Memory attributes are populated also for
 * page if mapping is found.
 * Return false if no block mapping is found for the address.
 */
bool get_block_info(const uint64_t addr, mblockinfo_t *block)
{
	uint64_t paddr, offt, tmp, i;
	struct entryinfo einfo;

	if (!block->guest)
		HYP_ABORT();

	if (block->stage == STAGE1)
		block->level = block->guest->table_levels_s1;
	else
		block->level = block->guest->table_levels_s2;
	paddr = __pt_walk(block->pgd, addr, &block->ptep, &block->level, &einfo);
	if (paddr == ~0UL) {
		block->type = INVALID_MEMORY;
		return false;
	}

	if (block->stage == STAGE1) {
		block->prot = *block->ptep & PROT_MASK_STAGE1;
		block->type = (*block->ptep & TYPE_MASK_STAGE1);
	} else {
		block->prot = *block->ptep & PROT_MASK_STAGE2;
		block->type = (*block->ptep & TYPE_MASK_STAGE2);
	}

	if (bit_raised(*block->ptep, CONTIGUOUS_BIT)) {
		/*
		 * Only 4k granule supported for now. Collect the 16 adjacent and
		 * aligned entries to the block information.
		 */
		tmp = (einfo.idx / MAX_CONTIGUOUS_4KGRANULE) * MAX_CONTIGUOUS_4KGRANULE;
		for (i = 0; i < MAX_CONTIGUOUS_4KGRANULE; i++)
			block->contiguous[i] = &einfo.ttbl->entries[i + tmp];
		if (i < MAX_CONTIGUOUS)
			block->contiguous[i] = NULL;
		if (*block->ptep != einfo.ttbl->entries[einfo.idx])
			HYP_ABORT();
	} else
		block->contiguous[0] = NULL;

	if (bit_raised(*block->ptep, TABLE_TYPE_BIT))
		return false;

	if (block->level == 1) {
		block->paddr = *block->ptep & tdinfo.l1_blk_oa_mask;
		block->size = tdinfo.l1_blk_size;
	} else {
		block->paddr = *block->ptep & tdinfo.l2_blk_oa_mask;
		block->size = tdinfo.l2_blk_size;
	}

	offt = paddr - block->paddr;
	block->vaddr = addr - offt;

	return true;
}

static int mmap_addr(mblockinfo_t *block, uint64_t vaddr, uint64_t paddr,
		     uint64_t range_size, uint64_t prot, uint64_t type,
		     uint64_t levels, uint32_t vmid)
{
	struct ptable *tp, *nl;
	uint64_t noff;
	int res = 0;

	tp = block->pgd;
	if (!tp || (vaddr > MAX_VADDR) || (paddr > MAX_PADDR))
		return -EINVAL;

	if (levels >= 4) {
		/*
		 * Level 0
		 */
		noff = (vaddr & TABLE_0_MASK) >> L0_SHIFT;
		nl = (struct ptable *)table_oaddr(tp->entries[noff]);
		if (!nl) {
			nl = alloc_table(block->tpool);
			if (!nl) {
				res = -ENOSPC;
				goto out_error;
			}

			tp->entries[noff] = (uint64_t)nl;
			bit_set(tp->entries[noff], VALID_TABLE_BIT);
			bit_set(tp->entries[noff], TABLE_TYPE_BIT);
		}
		tp = nl;
	}

	if (levels >= 3) {
		/*
		 * Level 1
		 */
		noff = (vaddr & TABLE_1_MASK) >> L1_SHIFT;
		nl = (struct ptable *)table_oaddr(tp->entries[noff]);
		if (range_size == (1 << L1_SHIFT)) {
			/*
			 * If this is a remap, verify there is no existing
			 * table we are going to overwrite.
			 */
			if (bit_raised(tp->entries[noff], TABLE_TYPE_BIT)) {
				free_table(block->tpool, (struct ptable *)
					   table_oaddr(tp->entries[noff]));
			}
			/* Clear all the fields other than output address */
			tp->entries[noff] = paddr & tdinfo.l1_blk_oa_mask;
			goto out_finalize;
		}
		if (!nl) {
			nl = alloc_table(block->tpool);
			if (!nl) {
				res = -ENOSPC;
				goto out_error;
			}

			tp->entries[noff] = (uint64_t)nl;
		}
		/* Since these can be remaps of blocks, assume nothing */
		tp->entries[noff] &= tdinfo.table_oa_mask;
		bit_set(tp->entries[noff], VALID_TABLE_BIT);
		bit_set(tp->entries[noff], TABLE_TYPE_BIT);
		tp = nl;
	}

	if (levels >= 2) {
		/*
		 * Level 2
		 */
		noff = (vaddr & TABLE_2_MASK) >> L2_SHIFT;
		if (range_size == (1 << L2_SHIFT)) {
			if (bit_raised(tp->entries[noff], TABLE_TYPE_BIT)) {
				free_table(block->tpool, (struct ptable *)
					   table_oaddr(tp->entries[noff]));
			}
			tp->entries[noff] = paddr & tdinfo.l2_blk_oa_mask;
			goto out_finalize;
		}
		nl = (struct ptable *)table_oaddr(tp->entries[noff]);
		if (!nl) {
			nl = alloc_table(block->tpool);
			if (!nl) {
				res = -ENOSPC;
				goto out_error;
			}

			tp->entries[noff] = (uint64_t)nl;
		}
		tp->entries[noff] &= tdinfo.table_oa_mask;
		bit_set(tp->entries[noff], VALID_TABLE_BIT);
		bit_set(tp->entries[noff], TABLE_TYPE_BIT);
		tp = nl;
	}

	/*
	 * Level 3, the page descriptor.
	 */
	noff = (vaddr & TABLE_3_MASK) >> L3_SHIFT;
	tp->entries[noff] = paddr & tdinfo.table_oa_mask;
	if (tp->entries[noff])
		bit_set(tp->entries[noff], TABLE_TYPE_BIT);

out_finalize:
	if (type == INVALID_MEMORY) {
		tp->entries[noff] = 0x0;
		res = 0;
		goto out_error;
	}
	/* Permissions and shareability of the area */
	tp->entries[noff] |= prot;

	/* Type of memory we refer to */
	tp->entries[noff] |= type;

	/* Validify it */
	bit_set(tp->entries[noff], VALID_TABLE_BIT);
	bit_set(tp->entries[noff], AF_BIT);

out_error:
	dsb();
	return res;
}

/*
 * Find the largest block size that can be mapped for this address
 * and range size.
 */
static uint64_t get_block_size(uint64_t vaddr, size_t length)
{
	uint64_t block_sz;

	if ((vaddr & tdinfo.l1_blk_offt_mask) == 0) {
		if (length >= tdinfo.l1_blk_size) {
			block_sz = tdinfo.l1_blk_size;
			goto out;
		}
	}
	if ((vaddr & tdinfo.l2_blk_offt_mask) == 0) {
		if (length >= tdinfo.l2_blk_size) {
			block_sz = tdinfo.l2_blk_size;
			goto out;
		}
	}
	block_sz = PAGE_SIZE;

out:
	return block_sz;
}

static void invalidate_va(uint64_t stage, uint64_t vaddr)
{
	if (!invalidate)
		return;

	dsb();
	if (stage == STAGE1)
		tlbi_el2_va(vaddr);
	if (stage == STAGE2)
		tlbi_el1_ipa(vaddr);
	dsb();
	isb();
}

int __mmap_range(mblockinfo_t *block, uint64_t vaddr, uint64_t paddr,
		 size_t length, uint64_t prot, uint64_t type,
		 uint64_t levels, uint32_t vmid)
{
	uint64_t blk_sz, new_blk_sz, tlength;
	int res;

	/* Return zero size mappings explicitly here.*/
	if (length <= 0)
		return 0;

	if (type > INVALID_MEMORY)
		return -EINVAL;

	vaddr = vaddr & VADDR_MASK;
	tlength = ROUND_UP(length, 0x1000);

	blk_sz = 0;
	while (tlength > 0) {
		spinner();

		new_blk_sz = get_block_size(vaddr, tlength);
		if (blk_sz != new_blk_sz)
			blk_sz = new_blk_sz;

		/*
		 * If this changes a currently existing hyp mode stage-1 OR active
		 * stage-2 mapping, do full break-before-make cycle.
		 */
		if (invalidate && paddr && (block->type != INVALID_MEMORY)) {
			res = mmap_addr(block, vaddr, 0x0, blk_sz, prot,
					INVALID_MEMORY, levels, vmid);
			if (res)
				return res;
			invalidate_va(block->stage, vaddr);
		}

		res = mmap_addr(block, vaddr, paddr, blk_sz, prot, type, levels,
				vmid);
		if (res)
			return res;

		if (invalidate && (block->type != INVALID_MEMORY))
			invalidate_va(block->stage, vaddr);

		vaddr += blk_sz;
		paddr += blk_sz;
		tlength -= blk_sz;
	}

	if (invalidate && (block->type != INVALID_MEMORY))
		tlbivmalle1is();
	dsb();
	isb();

	return 0;
}

static void __clear_contiguous_range(mblockinfo_t *block)
{
	uint64_t i, tmp;

	for (i = 0; i < MAX_CONTIGUOUS; i++) {
		if (!block->contiguous[i])
			break;

		tmp = *block->contiguous[i];
		bit_drop(tmp, CONTIGUOUS_BIT);
		*block->contiguous[i] = 0;
		dsbish();
		tlbialle1is();
		*block->contiguous[i] = tmp;
		dsbish();
		block->contiguous[i] = NULL;
		dsbish();
	}
	if (i % MAX_CONTIGUOUS_4KGRANULE)
			HYP_ABORT();
}

int __block_remap(uint64_t vaddr, size_t len, mblockinfo_t *block,
		  uint64_t paddr, uint64_t prot, uint64_t type,
		  uint64_t pgd_levels)
{
	uint64_t tvaddr, tpaddr, bsize;
	struct ptable *tbl;
	int res = 0;
	size_t rlen, tlen, mlen;
	uint32_t vmid = block->guest->vmid;
	bool hit;

	if (vmid != HOST_VMID) {
		load_guest_s2(vmid);
		isb();
	}

	if (len <= 0)
		goto out_done;

	/*
	 * For the sake of faster boot up it is left
	 * to the machine initialization code responsibility
	 * to make sure there is no overlapping mappings in
	 * initial configuration.
	 */
	if (!machine_init_ready()) {
		if (type == KEEP_MATTR)
			HYP_ABORT();
		res = __mmap_range(block, vaddr, paddr, len,
				   prot, type, pgd_levels, vmid);
		goto out_done;
	}

	tvaddr = vaddr;
	tpaddr = paddr;

	/*
	 * Map the new range and check for overlapping
	 * block mappings.
	 */
	rlen = len;
	while (rlen > 0) {
		hit = get_block_info(tvaddr, block);
		/*
		 * Tear down contiguous range of translation table entries.
		 */
		__clear_contiguous_range(block);
		if (hit) {
			/*
			 * If we are at the block boundary and the
			 * remaining length is equal (or larger)
			 * to the size of the block we found:
			 * We don't need to split the block.
			 * We may remap the whole block instead.
			 */
			if (((tvaddr & (block->size - 1)) == 0) &&
			    (rlen >= block->size)) {
				hit = false;
				bsize = block->size;
				mlen = block->size;
			}
		} else {
			/*
			 * There was no block mapped at tvaddr. We can
			 * map all until the next possibly mapped (level 2)
			 * block boundary.
			 */
			mlen = tdinfo.l2_blk_size -
			       (tvaddr & tdinfo.l2_blk_offt_mask);
			bsize = tdinfo.l2_blk_size;
		}
		if (hit) {
			/*
			 * Get a table entry into which we start building our
			 * new mapping. This will replace the block entry we
			 * found.
			 */
			tbl = alloc_table(block->tpool);
			if (!tbl)
				HYP_ABORT();

			/*
			 * Break. This should make the concurrent threads in
			 * other CPUs to generate an exception if they access
			 * the area mapped by this entry.
			 */
			*block->ptep = 0;
			dsbish();
			invalidate_va(block->stage, block->vaddr);
			tlbivmalle1is();
			dsb();
			isb();
			/*
			 * Replace the block entry.
			 */
			*block->ptep = (uint64_t)tbl;
			bit_set(*block->ptep, VALID_TABLE_BIT);
			bit_set(*block->ptep, TABLE_TYPE_BIT);
			dsbish();
			isb();

			/*
			 * Make. Create mapping for the address range covering
			 * the original block range before the vaddr.
			 */
			tlen = tvaddr - block->vaddr;
			res = __mmap_range(block, block->vaddr, block->paddr,
					   tlen, block->prot, block->type,
					   pgd_levels, vmid);
			if (res)
				HYP_ABORT();
			LOG("head v:0x%lx p:0x%lx l:%lu\n",
			    block->vaddr, block->paddr, tlen);
			block->vaddr += tlen;
			block->paddr += tlen;

			/* Size left within this block. */
			tlen = block->size - tlen;
			if (rlen < tlen) {
				mlen = rlen;
				tlen -= rlen;
				rlen = 0;
			} else {
				mlen = tlen;
				/* Map may reach the next block.*/
				rlen -= tlen;
				tlen = 0;
			}

			/* New range mapping */
			if (type == KEEP_MATTR)
				res = __mmap_range(block, tvaddr, tpaddr,
						   mlen, block->prot,
						   block->type, pgd_levels,
						   vmid);
			else
				res = __mmap_range(block, tvaddr, tpaddr,
						   mlen, prot, type,
						   pgd_levels, vmid);
			if (res)
				HYP_ABORT();
			LOG("map v:0x%lx l:%lu\n", tvaddr, mlen);
			tvaddr += mlen;
			tpaddr += mlen;
			block->vaddr += mlen;
			block->paddr += mlen;

			/*
			 * Create mapping for the address range covering the
			 * original block range after the vaddr + rlen.
			 */
			res = __mmap_range(block, block->vaddr, block->paddr,
					   tlen, block->prot, block->type,
					   pgd_levels, vmid);
			if (res)
				HYP_ABORT();

			LOG("tail v:0x%lx p:0x%lx l:%lu\n",
			    block->vaddr, block->paddr, tlen);
		} else {
			if (mlen == 0)
				mlen = bsize;
			if (mlen > rlen)
				mlen = rlen;
			if (type != KEEP_MATTR) {
				res = __mmap_range(block, tvaddr, tpaddr, mlen,
						   prot, type, pgd_levels, vmid);
			}
			if (res)
				HYP_ABORT();

			/*LOG("map nohit v:0x%lx l:%lu\n", tvaddr, mlen);*/
			tvaddr += mlen;
			tpaddr += mlen;
			rlen -= mlen;
		}
	}

out_done:
	if (vmid != HOST_VMID) {
		load_host_s2();
		isb();
	}
	return res;
}

int mmap_range(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
	       uint64_t paddr, size_t length, uint64_t prot, uint64_t type)
{
	uint64_t attr, nattr, val, *pte;
	kvm_guest_t *host;

	if (!guest || (vaddr > MAX_VADDR) || (paddr > MAX_PADDR) ||
	   (length > (SZ_1G * 4)))
		return -EINVAL;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	_zeromem16(&block, sizeof(block));

	switch (stage) {
	case STAGE2:
		if (!guest->EL1S2_pgd)
			return -ENOENT;

		block.guest = guest;

		block.pgd = guest->EL1S2_pgd;
		block.tpool = &guest->s2_tablepool;

		if (type == KERNEL_MATTR)
			type = (TYPE_MASK_STAGE2 & prot);
		prot &= PROT_MASK_STAGE2;

		if (block.guest != host)
			break;

		/* Unmap and 1:1 mapping allowed for the host */
		if ((vaddr != paddr) && paddr) {
			ERROR("Invalid host s2 map 0x%lx - 0x%lx\n",
				vaddr, paddr);
			return -EINVAL;
		}

		if (!(hostflags & HOST_STAGE2_LOCK))
			break;
		/*
		 * Reducing permissions allowed for locked
		 * kernel stage2 mapping. Allow remap for
		 * one page at a time.
		 */
		if (length != PAGE_SIZE)
			return -EPERM;

		__pt_walk(block.pgd, vaddr, &pte, 0, NULL);
		attr = (*pte &
			(PROT_MASK_STAGE2 | TYPE_MASK_STAGE2));
		nattr = (type | prot);

		/* Remap with same parameters denied */
		if (nattr == attr)
			return -EPERM;

		/* Write permission */
		if (nattr & S2AP_WRITE) {
			if (!(attr & S2AP_WRITE))
				return -EPERM;
		}

		/* Exec permission */
		val = (nattr & S2_XN_MASK);
		if (val != S2_EXEC_NONE) {
			if (val != (attr & S2_XN_MASK))
				return -EPERM;
		}

		nattr &= ~(S2AP_WRITE | S2_XN_MASK);
		attr &= ~(S2AP_WRITE | S2_XN_MASK);
		if (attr != nattr)
			return -EPERM;
		break;
	case STAGE1:
		/*
		 * This can be  either hosts own pool or a guest
		 * specific EL2 table pool.
		 */
		if (!guest->s1_tablepool.pool)
			return -ENOENT;

		/* Page global directory base address for EL2 is owned by host */
		block.guest = host;
		block.pgd = host->EL2S1_pgd;

		if (type == KERNEL_MATTR) {
			type = (TYPE_MASK_STAGE1 & prot);
			type = k2p_mattrindx(type);
		}
		prot &= PROT_MASK_STAGE1;

		if (hostflags & HOST_STAGE1_LOCK)
			return -EPERM;

		block.tpool = &guest->s1_tablepool;

		break;
	default:
		return -EINVAL;
	}

	if (!block.pgd || !block.guest || (length % PAGE_SIZE))
		return -EINVAL;

	block.stage = stage;

	return __block_remap(vaddr, length, &block, paddr, prot, type,
			     TABLE_LEVELS);
}

int unmap_range(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
		size_t length)
{
	kvm_guest_t *host;

	if (!guest || (vaddr > MAX_VADDR) || (length > (SZ_1G * 4)))
		return -EINVAL;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	switch (stage) {
	case STAGE2:
		block.guest = guest;
		block.pgd = guest->EL1S2_pgd;
		block.tpool = &block.guest->s2_tablepool;
		if (hostflags & HOST_STAGE2_LOCK)
			return -EPERM;
		break;
	case STAGE1:
		block.guest = host;
		block.pgd = host->EL2S1_pgd;
		if (hostflags & HOST_STAGE1_LOCK)
			return -EPERM;
		block.tpool = &guest->s1_tablepool;
		break;
	default:
		return -EINVAL;
	}

	if (!block.pgd || !block.guest || (length % PAGE_SIZE))
		return -EINVAL;

	block.stage = stage;

	return __block_remap(vaddr, length, &block, 0, 0, INVALID_MEMORY,
			     TABLE_LEVELS);
}

int user_copy(uint64_t dest, uint64_t src, uint64_t count,
	      uint64_t dest_pgd, uint64_t src_pgd)
{
	uint64_t dest_ipa, src_ipa;

	dest_ipa = __pt_walk((struct ptable *)dest_pgd, dest, 0, 0, NULL);
	if (dest_ipa == ~0UL)
		return -EINVAL;

	src_ipa = __pt_walk((struct ptable *)src_pgd, src, 0, 0, NULL);
	if (src_ipa == ~0UL)
		return -EINVAL;

	memcpy((void *)dest_ipa, (void *)src_ipa, count);
	return 0;
}

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

void enable_mmu(void)
{
	uint64_t sctlr;

	tlbialle1is();
	tlbialle2is();
	dsbish();
	isb();

	platform_mmu_prepare();

	sctlr = read_reg(SCTLR_EL2);
	bit_set(sctlr, SCTLR_MMU);
	bit_drop(sctlr, SCTLR_A);
	bit_set(sctlr, SCTLR_C);
	write_reg(SCTLR_EL2, sctlr);

	/*
	 * Make sure our mmu enable has been registered
	 * before proceeding any further.
	 */
	isb();
	tlbialle1is();
	tlbialle2is();
	tlbivmall();
	dsbish();
	isb();

	invalidate = 1;
	update_guest_state(guest_running);
}
