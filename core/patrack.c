// SPDX-License-Identifier: GPL-2.0-only
#include <stdlib.h>

#include "armtrans.h"
#include "tables.h"
#include "helpers.h"
#include "hvccall.h"
#include "patrack.h"

extern kvm_guest_t guests[MAX_VM];
extern uint16_t last_guest_index;

static void patrack_context_load(struct kvm_guest *guest)
{
	sys_context_t *host_ctxt;

	host_ctxt = get_guest_context(HOST_VMID, smp_processor_id());

	host_ctxt->ttbr0_el1 = read_reg(TTBR0_EL1);
	host_ctxt->ttbr1_el1 = read_reg(TTBR1_EL1);
	host_ctxt->vttbr_el2 = read_reg(VTTBR_EL2);
	write_reg(TTBR0_EL1, guest->patrack.ctxt.ttbr0_el1);
	write_reg(TTBR1_EL1, guest->patrack.ctxt.ttbr1_el1);
	write_reg(VTTBR_EL2, guest->ctxt[0].vttbr_el2);
	isb();
}

static void patrack_context_unload(void)
{
	sys_context_t *host_ctxt;

	host_ctxt = get_guest_context(HOST_VMID, smp_processor_id());

	write_reg(TTBR0_EL1, host_ctxt->ttbr0_el1);
	write_reg(TTBR1_EL1, host_ctxt->ttbr1_el1);
	write_reg(VTTBR_EL2, host_ctxt->vttbr_el2);
	isb();
}

static uint64_t patrack(struct kvm_guest *guest, uint64_t paddr)
{
	uint64_t par_el1;

	patrack_context_load(guest);

	par_el1 = (uint64_t)virt_to_phys((void *)paddr);

	patrack_context_unload();

	return par_el1;
}

struct kvm_guest *owner_of(uint64_t addr)
{
	uint64_t tmp;
	int i = 0;

	while (i < last_guest_index) {
		if (!guests[i].vmid || (guests[i].vmid == INVALID_VMID))
			goto cont;

		if (guests[i].vmid < GUEST_VMID_START)
			goto cont;

		tmp = patrack(&guests[i], addr);
		if (tmp != ~0UL)
			return &guests[i];

cont:
		i++;
	}
	/*
	 * Host must be returned as owner of the address ONLY IF the address was
	 * NOT mapped to any guest.
	 */
	return get_guest(HOST_VMID);
}

/*
 * Map a page table region for physical address tracker
 *
 * @param guest to map the page table region for
 * @param ipa for the range
 * @param paddr for the range
 * @return zero on success or error code on failure.
 */
int patrack_mmap_table(struct kvm_guest *guest, uint64_t ipa, uint64_t paddr,
		       uint64_t len)
{
	int res;
	struct kvm_guest *host = NULL;

	host = get_guest(HOST_VMID);
	if (!host)
		return -EINVAL;

	res = mmap_range(guest, STAGE2, ipa, paddr, len,
			 PAGE_HYP_RO | PATRACK_SH, S2_NORMAL_MEMORY);
	if (res) {
		ERROR("error %d!\n", res);
		return res;
	}

	res = mmap_range(host, EL2_STAGE1, ipa, paddr, len,
			 PAGE_KERNEL_RW | PATRACK_SH, NORMAL_WBACK_P);
	if (res)
		ERROR("error %d!\n", res);

	return res;
}

int patrack_unmap_table(struct kvm_guest *guest, uint64_t ipa, uint64_t len)
{
	int res;
	struct kvm_guest *host = NULL;

	host = get_guest(HOST_VMID);
	if (!host)
		return -EINVAL;

	res = unmap_range(guest, STAGE2, ipa, len);
	if (res) {
		ERROR("error %d!\n", res);
		return res;
	}

	res = unmap_range(host, EL2_STAGE1, ipa, len);
	if (res)
		ERROR("error %d!\n", res);

	return res;
}

struct ptable *patrack_set_table_offt(struct tablepool *tpool,
				      struct ptable *table)
{
	uint64_t offt = 0;

	/* If we are working on patrack page table */
	if (tpool == &tpool->guest->patrack.trailpool && (table != NULL)) {
		/* Adjust the page table ipa */
		offt = (uint64_t)table;
		table = (struct ptable *)(offt | PATRACK_TABLEOFFT);
	}

	return table;
}

int patrack_start(struct kvm_guest *guest)
{
	struct tablepool *tpool;
	struct ptable *pgd;
	uint64_t plen;
	int res;

	tpool = &guest->patrack.trailpool;
	pgd = alloc_pgd(guest, tpool);
	if (pgd == NULL)
		return -ENOMEM;

	plen = tpool->num_tables * sizeof(struct ptable);
	res = patrack_mmap_table(tpool->guest, (uint64_t)pgd,
				 (uint64_t)tpool->pool, plen);
	if (res)
		return res;

	guest->patrack.ctxt.ttbr0_el1 = (uint64_t)pgd;
	guest->patrack.EL1S1_0_pgd = pgd;

	pgd = alloc_table(tpool);
	if (pgd == NULL)
		return -ENOMEM;

	guest->patrack.ctxt.ttbr1_el1 = (uint64_t)pgd;

	return 0;
}

int patrack_stop(struct kvm_guest *guest)
{
	int c, res;
	struct tablepool *tpool;
	uint64_t tableipa;
	uint64_t tablephy;
	uint64_t tablelen;

	res = 0;

	tpool = &guest->patrack.trailpool;
	c = tpool->firstchunk;
	do {
		if (get_tablepool(tpool, c))
			break;
		tablephy = guest->mempool[c].start;
		tableipa = tablephy | PATRACK_TABLEOFFT;
		tablelen = guest->mempool[c].size;
		res = patrack_unmap_table(guest, tableipa, tablelen);
		if (res)
			ERROR("table unmap error: %d\n", res);
		c = guest->mempool[c].next;
	} while (c < GUEST_MEMCHUNKS_MAX);

	free_pgd(&guest->patrack.trailpool, NULL);

	return res;
}

/*
 * Mark a host physical address which is referenced multiple times by the given
 * guest.
 *
 * @param guest to mark the hpa for
 * @param hpa referenced by two or more gpa
 * @return zero on success or error code on failure.
 */
int patrack_hpa_set_multiref(struct kvm_guest *guest, uint64_t hpa)
{
	uint64_t *pte = NULL;

	pt_walk(guest, PATRACK_STAGE1, hpa, &pte);

	if (pte == NULL)
		HYP_ABORT();

	/*
	 * FIXME: If you see the abort below add a reference count
	 * implementation by increasing the reference count for the address if
	 * the condition below is true (and decreasing if the physical address
	 * with PATRACK_HPA_MULTIREF gets unmapped).
	 */
	if (*pte & PATRACK_HPA_MULTIREF)
		HYP_ABORT();

	*pte |= PATRACK_HPA_MULTIREF;

	return 0;
}

int patrack_hpa_is_multiref(struct kvm_guest *guest, uint64_t hpa)
{
	uint64_t *pte = NULL;

	pt_walk(guest, PATRACK_STAGE1, hpa, &pte);

	if ((pte != NULL) && (*pte & PATRACK_HPA_MULTIREF))
		return 1;

	return 0;
}

int patrack_mmap(struct kvm_guest *guest, uint64_t s1_addr, uint64_t ipa,
		 uint64_t length)
{
	int r, t = 0;
	struct tablepool *tpool;

	/*
	 * We can't map more page table memory while mapping the tracked
	 * addresses. Check that we have the worst case amount of table
	 * memory available for mapping. Starting from hint should be
	 * sufficient at this point.
	 */
	tpool = &guest->patrack.trailpool;
	for (r = tpool->hint; r < tpool->num_tables; r++) {
		if (!tpool->used[r])
			t++;
		if (t >= TABLE_LEVELS)
			break;
	}

	if ((t < TABLE_LEVELS) &&
	     guest->mempool[tpool->currentchunk].next == GUEST_MEMCHUNKS_MAX) {
		uint64_t plen;
		struct ptable *pool;

		/* Take a note on currently active pool */
		t = tpool->currentchunk;
		/* Allocate new pool */
		pool = alloc_tablepool(tpool);
		if (pool == NULL)
			return -ENOSPC;
		/* Map the new pool */
		pool = patrack_set_table_offt(tpool, pool);
		plen = tpool->num_tables * sizeof(struct ptable);
		r = patrack_mmap_table(tpool->guest, (uint64_t)pool,
				       (uint64_t)tpool->pool, plen);
		if (r)
			return r;
		/* And re-activate the current one */
		r = get_tablepool(tpool, t);
		if (r)
			return r;
	}

	return mmap_range(guest, PATRACK_STAGE1, s1_addr, ipa, length,
			  PAGE_KERNEL_RO | PATRACK_SH, NORMAL_WBACK_LINUX);
}

int patrack_unmap(struct kvm_guest *guest, uint64_t s1_addr, size_t length)
{
	if (patrack_hpa_is_multiref(guest, s1_addr)) {
		LOG("skip 0x%llx\n", s1_addr);
		return 0;
	}

	return unmap_range(guest, PATRACK_STAGE1, s1_addr, length);
}

uint64_t patrack_hpa2gpa(struct kvm_guest *guest, uint64_t hpa)
{
	return pt_walk(guest, PATRACK_STAGE1, hpa, NULL);
}

int patrack_validate_hpa(struct kvm_guest *host, struct kvm_guest *guest,
			 uint64_t hpa)
{
	uint64_t taddr;

	/*
	 * If the address is found from the host stage2 map we are good to
	 * return ok for both the blinded and the non-blinded cases.
	 */
	taddr = pt_walk(host, STAGE2, hpa, NULL);
	if (taddr != ~0UL)
		return 0;

	/*
	 * Address was not in host stage2 map. Check if the guest has mapped
	 * this address already.
	 */
	taddr = patrack(guest, hpa);
	if (taddr != ~0UL) {
		patrack_hpa_set_multiref(guest, hpa);
		return -EEXIST;
	}

	/*
	 * Address was not found from host or guest. Perhaps the address
	 * belongs to another guest?
	 */
	ERROR("g:0x%lx unknown hpa:0x%llx\n", guest, hpa);

	return -EPERM;
}

int patrack_gpa_set_share(struct kvm_guest *guest, uint64_t gpa, size_t length)
{
	uint64_t tgpa;

	if (!length || !guest || (gpa > guest->ramend))
		return -EINVAL;

	tgpa = gpa | PATRACK_SHAREOFFT;

	if (patrack_mmap(guest, tgpa, gpa, length))
		HYP_ABORT();

	return 0;
}

int patrack_gpa_clear_share(struct kvm_guest *guest, uint64_t gpa,
			    size_t length)
{
	uint64_t tgpa;

	if (!guest || !length)
		return -EINVAL;

	tgpa = gpa | PATRACK_SHAREOFFT;

	return patrack_unmap(guest, tgpa, length);
}

int patrack_gpa_is_share(struct kvm_guest *guest, uint64_t gpa, size_t length)
{
	int res = 0;
	uint64_t paddr, tgpa, agpa;
	ssize_t tlen;

	if (!guest || !length)
		return -EINVAL;

	patrack_context_load(guest);

	tgpa = gpa | PATRACK_SHAREOFFT;
	agpa = gpa;
	tlen = length;
	while (tlen > 0) {
		paddr = (uint64_t)virt_to_ipa((void *)tgpa);
		if (paddr == agpa) {
			res = 1;
			tlen -= PAGE_SIZE;
			tgpa += PAGE_SIZE;
			agpa += PAGE_SIZE;
		} else {
			res = 0;
			break;
		}
	}

	patrack_context_unload();

	return res;
}
