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
		paddr1 = pt_walk(guest->s2_pgd, vaddr1, &pte1, TABLE_LEVELS);
		if (paddr1 == ~0UL)
			goto cont;
		total += 1;

		paddr2 = pt_walk(host->s2_pgd, paddr1, &pte2, TABLE_LEVELS);
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

int print_mappings(uint32_t vmid, uint64_t stage)
{
	uint64_t start_vaddr = 0, end_vaddr = 0;
	uint64_t start_addr = 0, perms = ~0UL;
	uint64_t vaddr = 0, addr = 0, size = 0;
	uint64_t operms = ~0UL, oaddr = 0;
	kvm_guest_t *guest;
	struct ptable *pgd;
	int total = 0;
	uint64_t *pte;

	guest = get_guest(vmid);
	if (!guest) {
		ERROR("No such guest %u?\n", vmid);
		return -EINVAL;
	}
	switch (stage) {
	case STAGE2:
		pgd = guest->s2_pgd;
		break;
	case STAGE1:
		pgd = guest->s1_pgd;
		break;
	default:
		ERROR("Unknown stage?\n");
		return -EINVAL;
	}
	LOG("VMID %u pgd %p mappings %p - %p\n", vmid,
						(void *)pgd,
						(void *)vaddr,
						(void *)guest->ramend);
	LOG("vaddr\t\tpaddr\t\tsize\t\tprot\n");

	while (vaddr < guest->ramend) {
		pte = NULL;
		if (stage == STAGE1)
			addr = pt_walk(pgd, vaddr, &pte, guest->table_levels);
		else
			addr = pt_walk(pgd, vaddr, &pte, TABLE_LEVELS);

		/*
		 * Find the beginning
		 */
		if (addr == ~0UL) {
			vaddr += PAGE_SIZE;
			continue;
		}
		total++;
		/*
		 * Grab the perms
		 */
		if (stage == STAGE1)
			perms = *pte & PROT_MASK_STAGE1;
		else
			perms = *pte & PROT_MASK_STAGE2;
		if (operms == ~0UL)
			operms = perms;
		/*
		 * Seek to the end of the new mapping
		 */
		if ((addr == (oaddr + PAGE_SIZE)) && (perms == operms)) {
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
			LOG("0x%012lx\t0x%012lx\t0x%012lx\t0x%012lx\n",
			    start_vaddr, start_addr, size, operms);
		}
		/*
		 * Move along
		 */
		start_vaddr = vaddr;
		start_addr = addr;

		operms = perms;
		oaddr = addr;
		vaddr += PAGE_SIZE;
		end_vaddr = vaddr;
	}
	/* Last entry, if there is one  */
	if (!end_vaddr)
		return total;

	size = end_vaddr - start_vaddr;
	LOG("0x%012lx\t0x%012lx\t0x%012lx\t0x%012lx\n",
	     start_vaddr, start_addr, size, perms);

	return total;
}

int validate_host_mappings(void)
{
	uint64_t vaddr, end, ipa, phys1, phys2;
	kvm_guest_t *host;
	uint64_t *pgd;
	int ret = 0, count = 0;
	int i;

	if (get_current_vmid() != HOST_VMID) {
		ERROR("validation must be called in the host context\n");
		return -EFAULT;
	}

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	pgd = (uint64_t *)(read_reg(TTBR1_EL1) & TTBR_BADDR_MASK);
	if (!pgd)
		HYP_ABORT();

	for (i = 0; i < PT_SIZE_WORDS; i++) {
		if (pgd[i] == 0)
			continue;

		vaddr = i * SZ_1G;
		end = vaddr + SZ_1G;
		LOG("Scanning block %p - %p\n", vaddr, end);

		while (vaddr < end) {
			/*
			 * Hardware walk. This is done first to make sure we
			 * can even time this when needed.
			 */
			phys1 = (uint64_t)virt_to_phys((void *)vaddr);

			/* Software walk */
			phys2 = ~0UL;
			ipa = pt_walk((struct ptable *)pgd,
				     vaddr | LINUX_VA_FILL,
				     0, host->table_levels);
			if (ipa != ~0UL)
				phys2 = pt_walk(host->s2_pgd, ipa, 0,
						host->table_levels);

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
