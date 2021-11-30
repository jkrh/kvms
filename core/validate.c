#include "commondefines.h"
#include "guest.h"
#include "armtrans.h"
#include "validate.h"
#include "helpers.h"
#include "hvccall.h"

int count_shared(uint32_t vmid, bool lock)
{
	uint64_t paddr1, paddr2, vaddr1;
	kvm_guest_t *host;
	kvm_guest_t *guest;
	uint64_t *pte1, *pte2;
	int shared = 0, total = 0;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	guest = get_guest(vmid);
	if (!guest)
		return -EINVAL;

	vaddr1 = 0;
	while (vaddr1 <= GUEST_MEM_MAX) {
		paddr1 = pt_walk(guest, STAGE2, vaddr1, &pte1);
		if (paddr1 == ~0UL)
			goto cont;
		total += 1;

		paddr2 = pt_walk(host, STAGE2, paddr1, &pte2);
		if (paddr2 == ~0UL)
			goto cont;
		shared += 1;
#ifdef DEBUG
		LOG("Page %p is mapped in both the guest and the host\n", paddr2);
#endif
		if (lock) {
			*pte1 &= ~0x600000000000C0;
			*pte1 |= PAGE_HYP_RO;

			dsbish();
			isb();
			tlbi_el1_ipa(paddr1);
			dsbish();
			isb();
		}
cont:
		vaddr1 += PAGE_SIZE;
	}
	LOG("%d pages in the guest %u, total of %d shared with the host\n",
	    total, guest->vmid, shared);

	return shared;
}


char *parse_attrs(char *p, uint64_t attrs, uint64_t stage)
{
	const char *pv_access = "R-";
	const char *upv_access = "--";
	char pv_perm;
	char upv_perm;
	const char *mtype = "";

	if (p == 0) {
		if (stage == STAGE1)
			return "prv usr";
		else
			return "prv usr type";
	}

	if (stage == STAGE1) {
		pv_perm = (attrs & S1_PXN) ? '-' : 'X';
		upv_perm = (attrs & S1_UXN) ? '-' : 'X';

		switch (S1_AP(attrs)) {
		case 0b00:
			pv_access = "RW";
			upv_access = "--";
			break;
		case 0b01:
			pv_access = "RW";
			upv_access = "RW";
			if (pv_perm == 'X') {
				/* Not executable, because AArch64 execution
				 * treats all regions writable at EL0 as being PXN
				 */
				pv_perm = 'x';
			}
			break;
		case 0b10:
			upv_access = "R-";
			pv_access = "--";
			break;
		case 0b11:
			pv_access = "R-";
			upv_access = "R-";
			break;
		}
	} else if (stage == STAGE2) {
		switch (S2_XN(attrs)) {
		case 0b00:
			pv_perm =  'X';
			upv_perm = 'X';
			break;
		case 0b01:
			pv_perm = '-';
			upv_perm = 'X';
			break;
		case 0b10:
			pv_perm = '-';
			upv_perm = '-';
			break;
		case 0b11:
			pv_perm = 'X';
			upv_perm = '-';
		}

		switch (S2AP(attrs)) {
		case 0b00:
			pv_access = "--";
			upv_access = "--";
			break;
		case 0b01:
			pv_access = "R-";
			upv_access = "R-";
			break;
		case 0b10:
			pv_access = "-W";
			upv_access = "-W";
			break;
		case 0b11:
			pv_access = "RW";
			upv_access = "RW";
			break;
		}
		mtype = (S2_MEMTYPE(attrs) == S2_MEMTYPE_DEVICE) ? "Device" : "Normal";
	} else
		return "Unknown stage?";

	sprintf(p, "%s%c %s%c %s",
		pv_access, pv_perm, upv_access, upv_perm, mtype);
	return p;
}

int print_mappings(uint32_t vmid, uint64_t stage)
{
	uint64_t start_vaddr = 0, end_vaddr = 0;
	uint64_t start_addr = 0, attrs = ~0UL;
	uint64_t vaddr = 0, addr = 0, size = 0;
	uint64_t oattrs = ~0UL, oaddr = 0;
	kvm_guest_t *guest;
	int total = 0;
	uint64_t *pte;
	char buf[128];

	guest = get_guest(vmid);
	if (!guest) {
		ERROR("No such guest %u?\n", vmid);
		return -EINVAL;
	}

	switch (stage) {
	case STAGE2:
	case STAGE1:
	case STAGEA:
		break;
	default:
		ERROR("Unknown stage?\n");
		return -EINVAL;
	}
	LOG("VMID %u stage %u mappings %p - %p\n", vmid, stage,
					(void *)vaddr,
					(void *)guest->ramend);
	LOG("vaddr\t\tpaddr\t\tsize\t\tattributes         %s\n",
		parse_attrs(0, 0, stage));

	while (vaddr < guest->ramend) {
		pte = NULL;
		addr = pt_walk(guest, stage, vaddr, &pte);

		/*
		 * Find the beginning
		 */
		if (addr == ~0UL) {
			vaddr += PAGE_SIZE;
			continue;
		}
		total++;
		/*
		 * Grab the attrs
		 */
		attrs = *pte & ATTR_MASK;
		if (oattrs == ~0UL)
			oattrs = attrs;
		/*
		 * Seek to the end of the new mapping
		 */
		if ((addr == (oaddr + PAGE_SIZE)) && (attrs == oattrs)) {
			oaddr = addr;
			vaddr += PAGE_SIZE;
			end_vaddr = vaddr;
			continue;
		}
		/*
		 * Print it if there was something.
		 */
		if (end_vaddr) {
			size = end_vaddr - start_vaddr;
			LOG("0x%012lx\t0x%012lx\t0x%012lx\t0x%016lx %s\n",
			    start_vaddr, start_addr, size, oattrs,
			    parse_attrs(buf, oattrs, stage));
		}
		/*
		 * Move along
		 */
		start_vaddr = vaddr;
		start_addr = addr;

		oattrs = attrs;
		oaddr = addr;
		vaddr += PAGE_SIZE;
		end_vaddr = vaddr;
	}
	/* Last entry, if there is one  */
	if (!end_vaddr)
		return total;

	size = end_vaddr - start_vaddr;
	LOG("0x%012lx\t0x%012lx\t0x%012lx\t0x%016lx %s\n",
	     start_vaddr, start_addr, size, attrs,
	     parse_attrs(buf, attrs, stage));

	return total;
}

int print_mappings_el2(void)
{
	uint64_t start_vaddr = 0, end_vaddr = 0;
	uint64_t start_addr = 0, attrs = ~0UL;
	uint64_t vaddr = 0, addr = 0, size = 0;
	uint64_t oattrs = ~0UL, oaddr = 0;
	kvm_guest_t *host;
	uint64_t *pte;
	int total = 0;
	char buf[128];

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	LOG("EL2 mappings %p - %p\n", (void *)vaddr, host->ramend);
	LOG("vaddr\t\tpaddr\t\tsize\t\tattributes         %s\n",
		parse_attrs(0, 0, STAGE1));

	while (vaddr < host->ramend) {
		pte = NULL;
		addr = pt_walk_el2(vaddr, &pte);

		/*
		 * Find the beginning
		 */
		if (addr == ~0UL) {
			vaddr += PAGE_SIZE;
			continue;
		}
		total++;
		/*
		 * Grab the attrs
		 */
		attrs = *pte & ATTR_MASK;

		if (oattrs == ~0UL)
			oattrs = attrs;
		/*
		 * Seek to the end of the new mapping
		 */
		if ((addr == (oaddr + PAGE_SIZE)) && (attrs == oattrs)) {
			oaddr = addr;
			vaddr += PAGE_SIZE;
			end_vaddr = vaddr;
			continue;
		}
		/*
		 * Print it if there was something.
		 */
		if (end_vaddr) {
			size = end_vaddr - start_vaddr;
			LOG("0x%012lx\t0x%012lx\t0x%012lx\t0x%016lx %s\n",
			    start_vaddr, start_addr, size, oattrs,
			    parse_attrs(buf, oattrs, STAGE1));
		}
		/*
		 * Move along
		 */
		start_vaddr = vaddr;
		start_addr = addr;

		oattrs = attrs;
		oaddr = addr;
		vaddr += PAGE_SIZE;
		end_vaddr = vaddr;
	}
	/* Last entry, if there is one  */
	if (!end_vaddr)
		return total;

	size = end_vaddr - start_vaddr;
	LOG("0x%012lx\t0x%012lx\t0x%012lx\t0x%016lx %s\n",
	     start_vaddr, start_addr, size, attrs,
	     parse_attrs(buf, attrs, STAGE1));

	return total;
}

int validate_host_mappings(void)
{
	uint64_t vaddr, end, phys1, phys2;
	kvm_guest_t *host;
	uint64_t *pgd;
	uint32_t vmid;
	int ret = 0, count = 0;
	int i;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	vmid = get_current_vmid();
	if (vmid != HOST_VMID) {
		load_host_s2();
		isb();
	}

	if (!host->EL1S1_1_pgd)
		host->EL1S1_1_pgd = (struct ptable *)(read_reg(TTBR1_EL1) & TTBR_BADDR_MASK);
	pgd = (uint64_t *)host->EL1S1_1_pgd;

	for (i = 0; i < PT_SIZE_WORDS; i++) {
		if (pgd[i] == 0)
			continue;

		vaddr = i * SZ_1G | LINUX_VA_FILL;
		end = vaddr + SZ_1G;
		LOG("Scanning block %p - %p\n", vaddr, end);

		while (vaddr < end) {
			/*
			 * Hardware walk. This is done first to make sure we
			 * can even time this when needed.
			 */
			phys1 = (uint64_t)virt_to_phys((void *)vaddr);

			/* Software walk */
			phys2 = pt_walk(host, STAGEA, vaddr, 0);

			if (phys2 != ~0UL)
				count++;

			if (phys1 != phys2) {
				LOG("mismatch at virtual address %p: %p/%p\n",
				    vaddr, phys1, phys2);
				ret++;
			}

			vaddr += PAGE_SIZE;
		}
	}
	LOG("%d mapped pages, %d mismatches\n",  count, ret);

	if (vmid != HOST_VMID) {
		load_guest_s2(vmid);
		isb();
	}

	return ret;
}

void print_table(struct ptable *addr)
{
	uint64_t *ptr = (uint64_t *)addr;
	int i, z = 0, b = 0;

	for (i = 0; i < PT_SIZE_WORDS; i++) {
		if (!ptr[i])
			continue;
		if (!b) {
			printf("Table 0x%lx\n", addr);
			b = 1;
		}
		printf("%03d:0x%014lx ", i, ptr[i]);
		z++;
		if ((z % 4) == 0) {
			printf("\n");
			z = 0;
		}
	}
	if (b && ((z % 4) != 0))
		printf("\n");
}

void print_tables(uint64_t vmid)
{
	kvm_guest_t *guest;
	int c, i;

	guest = get_guest(vmid);
	if (!guest) {
		ERROR("No such guest %u?\n", vmid);
		return;
	}

	printf("Stage 2 page table data for vmid %lu ::::\n", vmid);

	c = guest->s2_tablepool.firstchunk;
	do {
		if (get_tablepool(&guest->s2_tablepool, c))
			break;
		for (i = 0; i < guest->s2_tablepool.num_tables; i++) {
			if (guest->s2_tablepool.used[i])
				print_table(&guest->s2_tablepool.pool[i]);
		}
		c = guest->mempool[c].next;
	} while (c < GUEST_MEMCHUNKS_MAX);
}
