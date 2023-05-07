// SPDX-License-Identifier: GPL-2.0-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

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
#include "tables.h"
#include "kvms_rs.h"
#include "oplocks.h"

#define DESCR_ATTR_MASK			0xFFFF00000001FFFFUL

#define MAX_PADDR			VADDR_MASK
#define MAX_VADDR			0xFFFFFFEFFFFFFFFFUL
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

extern spinlock_t *host_lock;
extern kvm_guest_t *host;
struct tdinfo_t tdinfo;
static uint64_t kmaidx2pmaidx[8];
static bool need_hyp_s1_init = true;

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

static uint8_t invalidate;
static mblockinfo_t block[PLATFORM_CORE_COUNT] ALIGN(16);

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
			panic("out of bounds\n");
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

static uint64_t __pt_walk(struct ptable *tbl, uint64_t vaddr, uint64_t **ptep,
			  uint64_t *levels, struct entryinfo *einfo)
{
	struct ptable *nl = tbl;
	uint64_t noff, boff, ret, addr = 0, lvl = 0;

	if (!levels || (*levels >= 4)) {
		/* Level 0 */
		noff = (vaddr & TABLE_0_MASK) >> L0_SHIFT;
		if (!bit_raised(nl->entries[noff], VALID_TABLE_BIT))
			return ~0UL;
		nl = (struct ptable *)table_oaddr(nl->entries[noff]);
		if (!nl)
			return ~0UL;
	}
	lvl++;

	if (!levels || (*levels >= 3)) {
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
	struct ptable *tbl;
	uint64_t addr, ipa, lvl;

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
		lvl = guest->table_levels_el1s2;
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

		lvl = guest->table_levels_el1s1;
		addr = __pt_walk(tbl, vaddr, ptep, &lvl, NULL);
		break;
	case PATRACK_STAGE1:
		lvl = guest->table_levels_el1s1;
		addr = __pt_walk(guest->patrack.EL1S1_0_pgd, vaddr, ptep, &lvl, NULL);
		break;
	default:
		addr = ~0UL;
		break;
	}
	return addr;
}

uint64_t pt_walk_el2(uint64_t vaddr, uint64_t **ptep)
{
	uint64_t lvl;

	lvl = host->table_levels_el2s1;
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
	struct ptable *nl;

	LOG("Area lock requested for kernel %p, size %lu bytes\n", vaddr, size);

	/*
	 * Don't go changing anything that's not there.
	 */
	ipa = pt_walk(host, STAGE2, vaddr, 0);
	if (ipa == ~0UL) {
		ERROR("Host kernel %p does not appear to be mapped\n", vaddr);
		return -EINVAL;
	}
	nl = host->EL1S2_pgd;
	levels = host->table_levels_el1s2;

	if (depth & 0x1)
		lock_kernel_page(host, (uint64_t)nl);

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
				lock_kernel_page(host, (uint64_t)nl);
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
				lock_kernel_page(host, (uint64_t)nl);
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
			lock_kernel_page(host, (uint64_t)nl);

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
static bool get_block_info(const uint64_t addr, mblockinfo_t *block)
{
	uint64_t paddr, offt, tmp, i;
	struct entryinfo einfo;

	if (!block->guest)
		panic("block with no owner?\n");

	if (block->stage == STAGE2)
		block->level = block->guest->table_levels_el1s2;
	else
		block->level = block->guest->table_levels_el2s1;

	paddr = __pt_walk(block->pgd, addr, &block->ptep, &block->level, &einfo);
	if (paddr == ~0UL) {
		block->type = INVALID_MEMORY;
		return false;
	}

	if (block->stage == STAGE2) {
		block->prot = *block->ptep & PROT_MASK_STAGE2;
		block->type = (*block->ptep & TYPE_MASK_STAGE2);
	} else {
		block->prot = *block->ptep & PROT_MASK_STAGE1;
		block->type = (*block->ptep & TYPE_MASK_STAGE1);
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
			panic("invalid pte\n");
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

	switch (stage) {
	case EL2_STAGE1:
		tlbi_el2_va(vaddr);
		break;
	case PATRACK_STAGE1:
		tlbi_el1_va(vaddr);
		break;
	case STAGE2:
		tlbi_el1_ipa(vaddr);
		break;
	default:
		break;
	}
	dsb();
	isb();
}

static int __mmap_range(mblockinfo_t *block, uint64_t vaddr, uint64_t paddr,
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
		panic("invalid range\n");
}

static int __block_remap(uint64_t vaddr, size_t len, mblockinfo_t *block,
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
			panic("invalid type\n");
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
				panic("table allocation failed\n");

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
				panic("__mmap_range failed with error %d\n", res);

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
				panic("__mmap_range failed with error %d\n", res);

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
				panic("__mmap_range failed with error %d\n", res);
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
				panic("__mmap_range failed with error %d\n", res);

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

int has_less_s2_perms(uint64_t nattr, uint64_t attr)
{
	uint64_t val;

	/* Write permission */
	if (nattr & S2AP_WRITE) {
		if (!(attr & S2AP_WRITE))
			return 0;
	}

	/* Exec permission */
	val = (nattr & S2_XN_MASK);
	if (val != S2_EXEC_NONE) {
		if (val != (attr & S2_XN_MASK))
			return 0;
	}

	nattr &= ~(S2AP_WRITE | S2_XN_MASK);
	attr &= ~(S2AP_WRITE | S2_XN_MASK);
	if (attr != nattr)
		return 0;

	return 1;
}

int mmap_range_unlocked(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
			uint64_t paddr, size_t length, uint64_t prot,
			uint64_t type)
{
	uint64_t attr, nattr, *pte, pgd_levels;
	int cid, res;

	if (!guest || (vaddr > MAX_VADDR) || (paddr > MAX_PADDR) ||
	    (length > (SZ_1G * 4)))
		return -EINVAL;

	cid = smp_processor_id();
	_zeromem16(&block[cid], sizeof(mblockinfo_t));

	switch (stage) {
	case STAGE2:
		if (!guest->EL1S2_pgd) {
			res = -ENOENT;
			goto out;
		}

		block[cid].guest = guest;
		block[cid].pgd = guest->EL1S2_pgd;
		block[cid].tpool = &guest->s2_tablepool;

		if (type == KERNEL_MATTR)
			type = (TYPE_MASK_STAGE2 & prot);
		prot &= PROT_MASK_STAGE2;

		pgd_levels = block[cid].guest->table_levels_el1s2;

		if (block[cid].guest != host)
			break;

		/*
		 * Unmap and 1:1 mapping allowed for the host so the blinded
		 * VMs also run with the locks on.
		 */
		if ((vaddr != paddr) && (type != INVALID_MEMORY)) {
			res = -EINVAL;
			goto out;
		}

		if (!(is_locked(HOST_STAGE2_LOCK)))
			break;

		/*
		 * Reducing permissions allowed for locked kernel stage2
		 * mapping. Allow remap for one page at a time.
		 */
		if (length != PAGE_SIZE) {
			res = -EPERM;
			goto out;
		}

		if (__pt_walk(block[cid].pgd, vaddr, &pte, 0, NULL) == ~0UL) {
			res = -EPERM;
			goto out;
		}

		attr = (*pte &
			(PROT_MASK_STAGE2 | TYPE_MASK_STAGE2));
		nattr = (type | prot);

		/* Remap with same parameters denied */
		if (nattr == attr) {
			res = -EPERM;
			goto out;
		}

		if (!has_less_s2_perms(nattr, attr)) {
			res = -EPERM;
			goto out;
		}
		break;
	case EL2_STAGE1:
		/* Page global directory base address for EL2 is owned by host */
		block[cid].guest = host;
		block[cid].pgd = host->EL2S1_pgd;

		if (type == KERNEL_MATTR) {
			type = (TYPE_MASK_STAGE1 & prot);
			type = k2p_mattrindx(type);
		}
		prot &= PROT_MASK_STAGE1;

		if (is_locked(HOST_STAGE1_LOCK)) {
			res = -EPERM;
			goto out;
		}

		block[cid].tpool = &host->el2_tablepool;
		pgd_levels = block[cid].guest->table_levels_el2s1;

		break;
	case PATRACK_STAGE1:
		if (!guest->patrack.EL1S1_0_pgd) {
			res = -ENOENT;
			goto out;
		}

		block[cid].guest = guest;
		block[cid].pgd = guest->patrack.EL1S1_0_pgd;
		block[cid].tpool = &guest->patrack.trailpool;
		pgd_levels = block[cid].guest->table_levels_el1s1;
		break;
	default:
		res = -EINVAL;
		goto out;
		break;
	}

	if (!block[cid].pgd || !block[cid].guest || (length % PAGE_SIZE)) {
		res = -EINVAL;
		goto out;
	}

	block[cid].stage = stage;
	res = __block_remap(vaddr, length, &block[cid], paddr, prot, type,
			    pgd_levels);

out:
	return res;
}

int mmap_range(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
	       uint64_t paddr, size_t length, uint64_t prot, uint64_t type)
{
	int res;

	spin_lock(&guest->hvc_lock);
	res = mmap_range_unlocked(guest, stage, vaddr, paddr, length,
				  prot, type);
	spin_unlock(&guest->hvc_lock);

	return res;
}

int unmap_range_unlocked(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
			 size_t length)
{
	uint64_t pgd_levels;
	int cid, res;

	if (!guest || (vaddr > MAX_VADDR) || (length > (SZ_1G * 4)))
		return -EINVAL;

	cid = smp_processor_id();
	switch (stage) {
	case STAGE2:
		if (is_locked(HOST_STAGE2_LOCK)) {
			res = -EPERM;
			goto out;
		}

		block[cid].guest = guest;
		block[cid].pgd = guest->EL1S2_pgd;
		block[cid].tpool = &block[cid].guest->s2_tablepool;
		pgd_levels = block[cid].guest->table_levels_el1s2;
		break;
	case EL2_STAGE1:
		if (is_locked(HOST_STAGE1_LOCK)) {
			res = -EPERM;
			goto out;
		}
		block[cid].guest = host;
		block[cid].pgd = host->EL2S1_pgd;
		block[cid].tpool = &host->el2_tablepool;
		pgd_levels = block[cid].guest->table_levels_el2s1;
		break;
	case PATRACK_STAGE1:
		if (!guest->patrack.EL1S1_0_pgd) {
			res = -ENOENT;
			goto out;
		}

		block[cid].guest = guest;
		block[cid].pgd = guest->patrack.EL1S1_0_pgd;
		block[cid].tpool = &guest->patrack.trailpool;
		pgd_levels = block[cid].guest->table_levels_el1s1;
		break;
	default:
		res = -EINVAL;
		goto out;
	}

	if (!block[cid].pgd || !block[cid].guest || (length % PAGE_SIZE)) {
		res = -EINVAL;
		goto out;
	}

	block[cid].stage = stage;
	res = __block_remap(vaddr, length, &block[cid], 0, 0, INVALID_MEMORY,
			    pgd_levels);

out:
	return res;
}

int unmap_range(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr,
		size_t length)
{
	int res;

	spin_lock(&guest->hvc_lock);
	res = unmap_range_unlocked(guest, stage, vaddr, length);
	spin_unlock(&guest->hvc_lock);

	return res;
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
	bit_set(sctlr, SCTLR_SA);
	bit_set(sctlr, SCTLR_I);
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
	update_guest_state(GUEST_RUNNING);
}
