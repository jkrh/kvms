// SPDX-License-Identifier: GPL-2.0-only

#include "commondefines.h"
#include "guest.h"
#include "armtrans.h"
#include "validate.h"
#include "helpers.h"
#include "hvccall.h"
#include "spinlock.h"
#include "bits.h"
#include "imath.h"
#include "tables.h"
#include "keystore.h"
bool at_debugstop = false;
extern spinlock_t core_lock;

#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"

#define CHECKRES(x) if (x != MBEDTLS_EXIT_SUCCESS) return -EFAULT;

int debugstop(void)
{
	spin_lock(&core_lock);
	at_debugstop = true;
	return 0;
}

int debugstart(void)
{
	spin_unlock(&core_lock);
	at_debugstop = false;
	return 0;
}

int count_shared(uint32_t vmid, bool lock)
{
	uint64_t paddr1, paddr2, vaddr1;
	kvm_guest_t *host;
	kvm_guest_t *guest;
	uint64_t *pte1, *pte2;
	int shared = 0, total = 0;

	host = get_guest(HOST_VMID);
	if (!host)
		panic("");

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
		LOG("Page %p is mapped in both the guest and the host\n",
		    paddr2);
#endif
		if (lock) {
			*pte1 &= ~(S2_XN_MASK & S2AP_MASK);
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

int print_shares(uint32_t vmid)
{
	kvm_guest_t *guest;
	uint64_t slot_start, slot_end, size;
	uint64_t phys;
	size_t p = 0, t = 0;
	int i;

	guest = get_guest(vmid);
	if (!guest) {
		ERROR("No such guest %u?\n", vmid);
		return -ENOENT;
	}

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++) {
		if (!guest->slots[i].slot.npages)
			continue;

		slot_start = fn_to_addr(guest->slots[i].slot.base_gfn);
		slot_end = slot_start;
		size = guest->slots[i].slot.npages * PAGE_SIZE;

		while (slot_end <= (slot_start + size)) {
			if (is_share(guest, slot_end, PAGE_SIZE) == 1) {

				phys = pt_walk(guest, STAGE2, slot_end, 0);
				if (phys != ~0UL)
					p++;

				t++;

				LOG("Guest share at gpa 0x%016llx -> 0x%016llx, len %d\n",
					slot_end, phys, PAGE_SIZE);
			}
			slot_end += PAGE_SIZE;
		}
	}
	LOG("Total of %d guest declared shares of which %d are mapped\n",
	     t, p);

	return p;
}

char *parse_attrs(char *p, uint64_t attrs, uint64_t stage)
{
	const char *pv_access = "R-";
	const char *upv_access = "--";
	char pv_perm = '-';
	char upv_perm = '-';
	const char *mtype = "";

	if (p == 0) {
		if (stage == STAGE2)
			return "prv usr type";
		else
			return "prv usr";
	}

	if ((stage == STAGE1) || (stage == EL2_STAGE1)) {
		pv_perm = (attrs & S1_PXN) ? '-' : 'X';
		upv_perm = (attrs & S1_UXN) ? '-' : 'X';

		switch (attrs & S1_AP_MASK) {
		case S1_AP_RW_N:
			pv_access = "RW";
			upv_access = "--";
			break;
		case S1_AP_RW_RW:
			pv_access = "RW";
			upv_access = "RW";
			if (pv_perm == 'X') {
				/* Not executable, because AArch64 execution
				 * treats all regions writable at EL0 as being PXN
				 */
				pv_perm = 'x';
			}
			break;
		case S1_AP_RO_N:
			pv_access = "R-";
			upv_access = "--";
			break;
		case S1_AP_RO_RO:
			pv_access = "R-";
			upv_access = "R-";
			break;
		}
	} else if (stage == STAGE2) {
		switch (attrs & S2_XN_MASK) {
		case S2_EXEC_EL1EL0:
			pv_perm =  'X';
			upv_perm = 'X';
			break;
		case S2_EXEC_EL0:
			pv_perm = '-';
			upv_perm = 'X';
			break;
		case S2_EXEC_NONE:
			pv_perm = '-';
			upv_perm = '-';
			break;
		case S2_EXEC_EL1:
			pv_perm = 'X';
			upv_perm = '-';
		}

		switch (attrs & S2AP_MASK) {
		case S2AP_NONE:
			pv_access = "--";
			upv_access = "--";
			break;
		case S2AP_READ:
			pv_access = "R-";
			upv_access = "R-";
			break;
		case S2AP_WRITE:
			pv_access = "-W";
			upv_access = "-W";
			break;
		case S2AP_RW:
			pv_access = "RW";
			upv_access = "RW";
			break;
		}
		mtype = ((attrs & S2_MEM_TYPE_MASK) == S2_DEVICE) ? "Device" :
								   "Normal";
	} else
		return "Unknown stage?";

	sprintf(p, "%s%c %s%c %s", pv_access, pv_perm, upv_access, upv_perm,
		mtype);
	return p;
}

int print_range(kvm_guest_t *guest, uint64_t stage, uint64_t vaddr, uint64_t end)
{
	uint64_t start_vaddr = 0, end_vaddr = 0;
	uint64_t start_addr = 0, attrs = ~0UL;
	uint64_t oattrs = ~0UL, oaddr = 0;
	uint64_t addr = 0, size = 0;
	uint64_t *pte;
	int total = 0;
	char buf[128];

	if ((end - vaddr) > PAGE_SIZE) {
		LOG("VMID %u stage %u mappings %p - %p\n", guest->vmid, stage,
		    (void *)vaddr, (void *)end);
		LOG("vaddr               paddr               size                attributes          %s\n",
		    parse_attrs(0, 0, stage));
	}

	while (vaddr < end) {
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
			LOG("0x%016lx  0x%016lx  0x%016lx  0x%016lx  %s\n",
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
	LOG("0x%016lx  0x%016lx  0x%016lx  0x%016lx  %s\n", start_vaddr,
	    start_addr, size, attrs, parse_attrs(buf, attrs, stage));

	return total;
}

int print_mappings(uint32_t vmid, uint64_t stage)
{
	uint64_t vaddr = 0;
	kvm_guest_t *guest;
	int total = 0;

	guest = get_guest(vmid);
	if (!guest) {
		ERROR("No such guest %u?\n", vmid);
		return -EINVAL;
	}

	switch (stage) {
	case STAGEA:
	case STAGE2:
		return print_range(guest, stage, vaddr, guest->ramend);
	case STAGE1:
		/* Kernel logical map */
		vaddr = el1_fill();
		total += print_range(guest, stage, vaddr, vaddr + (4 * SZ_1G));

		/* Kasan shadow region */
		bit_set(vaddr, 63 - TCR_EL1_T1SZ(read_reg(TCR_EL1)));
		total += print_range(guest, stage, vaddr, vaddr + (4 * SZ_1G));

		break;
	default:
		ERROR("Unknown stage?\n");
		return -EINVAL;
	}
	return total;
}

int print_share_area(uint32_t vmid)
{
	kvm_guest_t *guest;

	guest = get_guest(vmid);
	if (!guest) {
		ERROR("No such guest %u?\n", vmid);
		return -ENOENT;
	}

	return print_range(guest, PATRACK_STAGE1, PATRACK_SHAREOFFT, PATRACK_SHAREOFFT + (SZ_1G * 4));
}

int print_addr(uint32_t vmid, uint64_t stage, uint64_t addr)
{
	uint64_t vaddr = 0;
	kvm_guest_t *guest;

	guest = get_guest(vmid);
	if (!guest) {
		ERROR("No such guest %u?\n", vmid);
		return -EINVAL;
	}

	vaddr = (addr & PAGE_MASK);

	return print_range(guest, stage, vaddr, vaddr + PAGE_SIZE);
}

uint64_t translate_addr(uint64_t vaddr)
{
	uint64_t paddr;

	paddr = (uint64_t)virt_to_phys((void *)vaddr);

	LOG("vaddr\t\t\tpaddr\n");
	LOG("0x%016lx\t0x%012lx\n", vaddr, paddr);

	return paddr;
}

int __print_mappings_el2(uint64_t ivaddr, uint64_t iend)
{
	uint64_t start_vaddr = 0, end_vaddr = 0;
	uint64_t start_addr = 0, attrs = ~0UL;
	uint64_t vaddr = ivaddr, addr = 0, size = 0;
	uint64_t oattrs = ~0UL, oaddr = 0;
	uint64_t *pte;
	int total = 0;
	char buf[128];

	LOG("EL2 mappings %p - %p\n", (void *)vaddr, iend);
	LOG("vaddr               paddr               size                attributes          %s\n",
	    parse_attrs(0, 0, EL2_STAGE1));

	while (vaddr < iend) {
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
			LOG("0x%016lx  0x%016lx  0x%016lx  0x%016lx  %s\n",
			    start_vaddr, start_addr, size, oattrs,
			    parse_attrs(buf, oattrs, EL2_STAGE1));
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
	LOG("0x%016lx  0x%016lx  0x%016lx  0x%016lx  %s\n", start_vaddr,
	    start_addr, size, attrs, parse_attrs(buf, attrs, EL2_STAGE1));

	return total;
}

int print_mappings_el2()
{
	int total = 0;
	kvm_guest_t *host;

	host = get_guest(HOST_VMID);
	if (!host)
		panic("");
	/* HYP mappings */
	total += __print_mappings_el2(0, host->ramend);
	/* Generic KVM HYP mappings */
	total += __print_mappings_el2(KERNEL_BASE, KERNEL_BASE + (KERNEL_BASE-1));

	return total;
}

int validate_host_mappings(void)
{
	uint64_t vaddr, end, phys1, phys2, fill;
	kvm_guest_t *host;
	uint64_t *pgd;
	uint32_t vmid;
	int ret = 0, count = 0;
	int i;

	host = get_guest(HOST_VMID);
	if (!host)
		panic("");

	vmid = get_current_vmid();
	if (vmid != HOST_VMID) {
		load_host_s2();
		isb();
	}

	fill = el1_fill();
	host->EL1S1_1_pgd = (struct ptable *)(read_reg(TTBR1_EL1) &
					      TTBR_BADDR_MASK);
	pgd = (uint64_t *)host->EL1S1_1_pgd;

	for (i = 0; i < PT_SIZE_WORDS; i++) {
		if (pgd[i] == 0)
			continue;

		vaddr = i * SZ_1G | fill;
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
	LOG("%d mapped pages, %d mismatches\n", count, ret);

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


int print_encryption_state(uint32_t vmid)
{
	mbedtls_sha256_context c;
	kvm_guest_t *guest;
	kvm_page_data *pd;
	uint8_t sha256[32];
	uint64_t ipa;
	int z = 0, ret;

	guest = get_guest(vmid);
	if (!guest) {
		ERROR("No such guest %u?\n", vmid);
		return -EINVAL;
	}

	printf("\nScanning guest ram range 0 - 0x%lx\n", guest->ramend);

	printf("Address\t\tIntegrity\t\t\tEncr\tIntegrity\n");
	for (ipa = 0; ipa < guest->ramend; ipa += PAGE_SIZE) {
		pd = get_range_info(guest, ipa);
		if (!pd)
			continue;

		printf("0x%lx\t", ipa);

		for (int i = 0; i < 8; i++)
			printf("%02hhx:", pd->sha256[i]);

		printf("..\t");

		if (pd->nonce)
			printf("y\t");
		else
			printf("n\t");

		if (vmid == HOST_VMID) {
			mbedtls_sha256_init(&c);
			ret = mbedtls_sha256_starts_ret(&c, 0);
			CHECKRES(ret);

			ret = mbedtls_sha256_update_ret(&c, (void *)pd->phys_addr,
							PAGE_SIZE);
			CHECKRES(ret);

			ret = mbedtls_sha256_finish_ret(&c, sha256);
			CHECKRES(ret);

			ret = memcmp(sha256, pd->sha256, 32);
			if (ret != 0)
				printf("FAIL\n");
			else
				printf("OK\n");
		}

		z++;
	}
	return z;
}

void validate_keys(uint64_t vmid)
{
	kvm_guest_t *guest;
	const uint8_t guest_id[] = "test12test";
	uint8_t key[32];
	uint8_t buf[128];
	size_t size = sizeof(buf);
	size_t len = sizeof(key);
	int res;

	guest = get_guest(vmid);
	if (!guest) {
		ERROR("No such guest %u?\n", vmid);
		return;
	}
	res = set_guest_id(guest, guest_id, sizeof(guest_id));
	res = generate_key(guest, key, &len, 1, "test1");
	uint64_t *p = (uint64_t *)&key[0];
	printf("res %x len %d\n", res, len);
	printf("%llx %llx %llx %llx\n", p[0], p[1], p[2], p[3]);

	res = save_vm_key(guest, buf, &size);
	printf("res %x size %d\n", res, size);
	res = generate_key(guest, key, &len, 1, "test1");
	printf("%llx %llx %llx %llx\n", p[0], p[1], p[2], p[3]);

	res = load_vm_key(guest, buf, size);
	printf("res %x size %d\n", res, size);
	res = get_key(guest, key, &len, 1, "test1");
	printf("res %x len %d\n", res, len);
	printf("%llx %llx %llx %llx\n", p[0], p[1], p[2], p[3]);
}
