#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "platform_api.h"
#include "host_platform.h"
#include "product_api.h"
#include "product.h"
#include "armtrans.h"
#include "helpers.h"
#include "hvccall.h"
#include "bits.h"

#define PHYS_OFFSET 0x40000000UL

#define LPUART_STAT_TDRE	0x800000 /* Transmit Data Register Empty Flag */
#define LPUART_STAT_TC		0x400000 /* Transmission Complete Flag */

#define LPUART_STAT		5 /* LPUART Status Register (STAT) */
#define LPUART_DATA		7 /* LPUART Data Register (DATA) */

uint8_t __stack[STACK_SIZE * PLATFORM_CORE_COUNT] ALIGN(16) DATA;

static bool init_ready;

typedef struct {
	uint64_t start;
	uint64_t end;
	uint64_t phys;
	uint64_t range_size;
	uint64_t type; /* Stage 1 AttrIndx and stage 2 MemAttr */
	uint64_t share;
	uint64_t perms;
} memmap;

typedef struct {
	uint64_t start;
	uint64_t end;
} memrange;

#include "product_mmap.h"

int map_table(kvm_guest_t *host, int stage, const memmap *mm)
{
	int res = 0, i;

	i = 0;
	while (mm[i].range_size) {
		uint64_t len, attributes;

		len = (mm[i].end - mm[i].start) + 1;
		attributes = mm[i].perms | (mm[i].share << SH_SHIFT);

		res = mmap_range(host, stage, mm[i].start, mm[i].phys,
				 len, attributes, mm[i].type);
		if (res)
			break;
		i++;
	}

	return res;
}

void platform_init_slots(kvm_guest_t *host)
{
	/*
	 * Placeholder.
	 */
	host->slots[0].slot.base_gfn = 0;
	host->slots[0].slot.npages = 1 << (39 - PAGE_SHIFT);
}

int machine_init(kvm_guest_t *host)
{
	int res;
	size_t len;

	init_ready = false;

	host->s2_host_access = true;

	res = map_table(host, EL2_STAGE1, base_memmap);
	if (res)
		return res;

	res = map_table(host, STAGE2, st2_base_memmap);
	if (res)
		return res;

	/*
	 * Mark the init ready as we have the initial platform memory maps
	 * in place. From this on let the mapper logic do some additional
	 * checking on overlapping mappings etc.
	 */
	init_ready = true;

	/* Hyp EL2 text */
	len = BL_CODE_LIMIT - BL_CODE_BASE;
	res = mmap_range(host, EL2_STAGE1, BL_CODE_BASE, BL_CODE_BASE,
			 len, PAGE_KERNEL_EXEC | EL2S1_SH, NORMAL_WBACK_P);
	if (res)
		return res;

	res = unmap_range(host, STAGE2, BL_CODE_BASE, len);
	if (res)
		return res;
	/* Hyp EL2 data */
	len = BL1_RAM_LIMIT - BL1_RAM_BASE;
	res = mmap_range(host, EL2_STAGE1, BL1_RAM_BASE, BL1_RAM_BASE,
			 len, PAGE_KERNEL_RW | EL2S1_SH, NORMAL_WBACK_P);
	if (res)
		return res;

	res = unmap_range(host, STAGE2, BL1_RAM_BASE, len);
	if (res)
		return res;

	/* Initial slots for host */
	platform_init_slots(host);

	return res;
}

bool machine_init_ready(void)
{
	return init_ready;
}

static inline uint8_t reverse(uint8_t b)
{
	return (uint8_t)((b * 0x0202020202UL & 0x010884422010UL) % 1023UL);
}

int platform_entropy(uint8_t *entropy, size_t len)
{
	uint64_t v1, v2;
	uint8_t b1, b2;
	/*
	 * Our 'very secure' development entropy.
	 */
	while (len-- > 0) {
		wfe();
		v1 = read_reg(CNTPCT_EL0);
		b1 = v1 & 0xFF;

		wfe();
		v2 = read_reg(CNTPCT_EL0);
		b2 = v2 & 0xFF;

		b2 = reverse(b2);
		b1 ^= b2;
		entropy[len] = b1;
	}
	return 0;
}

int platform_init_host_pgd(kvm_guest_t *host)
{
	if (!host)
		return -EINVAL;

	host->EL2S1_pgd = alloc_pgd(host, &host->el2_tablepool);
	host->EL1S2_pgd = alloc_pgd(host, &host->s2_tablepool);

	if (!host->EL2S1_pgd || !host->EL1S2_pgd)
		return -ENOMEM;

	host->table_levels_el2s1 = TABLE_LEVELS;
	host->table_levels_el1s1 = TABLE_LEVELS;
	host->table_levels_el1s2 = TABLE_LEVELS;

	return 0;
}

void platform_early_setup(void)
{
	uint64_t hcr_el2, cnthctl_el2;

	/* 64 bit only, Trap SMCs */
	hcr_el2 = 0;
	bit_set(hcr_el2, HCR_RW_BIT);
	bit_set(hcr_el2, HCR_VM_BIT);
	bit_set(hcr_el2, HCR_NV2_BIT);
	bit_set(hcr_el2, HCR_TVM_BIT);
	write_reg(HCR_EL2, hcr_el2);

	/* EL1 timer access */
	cnthctl_el2 = 0;
	bit_set(cnthctl_el2, CNTHCTL_EL1PCTEN_BIT);
	bit_set(cnthctl_el2, CNTHCTL_EL1PCEN_BIT);
	bit_set(cnthctl_el2, CNTHCTL_ENVTEN_BIT);
	write_reg(CNTHCTL_EL2, cnthctl_el2);
	write_reg(CNTVOFF_EL2, 0);

	/* Processor id */
	write_reg(VPIDR_EL2, read_reg(MIDR_EL1));

	/* Use linux mair */
	write_reg(MAIR_EL2, PLATFORM_MAIR_EL2);

	isb();
}

void platform_mmu_prepare(void)
{
	kvm_guest_t *host;

	if (PLATFORM_VTCR_EL2 != 0)
		write_reg(VTCR_EL2, PLATFORM_VTCR_EL2);

	if (PLATFORM_TCR_EL2 != 0)
		write_reg(TCR_EL2, PLATFORM_TCR_EL2);

	host = get_guest(HOST_VMID);
	if (!host)
		panic("");

	write_reg(TTBR0_EL2, (uint64_t)host->EL2S1_pgd);
	write_reg(VTTBR_EL2, (uint64_t)host->EL1S2_pgd);
	set_current_vmid(HOST_VMID);

	dsb();
	isb();
}

uint32_t platform_get_next_vmid(uint32_t next_vmid)
{
	int i;
	kvm_guest_t *guest;

	if (next_vmid <= GUEST_VMID_START)
		next_vmid = GUEST_VMID_START;

	for (i = next_vmid; i < PRODUCT_VMID_MAX; i++) {
		guest = get_guest(i);
		if (!guest) {
			next_vmid = i;
			break;
		}
	}
	return next_vmid;
}

#ifdef DEBUG
int _IO_putc(int c, struct _IO_FILE *__fp)
{
	uint32_t val;
	volatile uint32_t *uart = (uint32_t *)PRODUCT_UART_BASE;

	do {
		val = *(uart + LPUART_STAT);
	} while (!(val & LPUART_STAT_TDRE));

	*(uint8_t *)(uart + LPUART_DATA) = c;

	do {
		val = *(uart + LPUART_STAT);
	} while (!(val & LPUART_STAT_TC));

	return 0;
}
#endif

void platform_console_init(void)
{
#ifdef DEBUG
	// Add UART init if any needed
#endif /* DEBUG */
}

uint8_t *platfrom_get_stack_ptr(uint64_t init_index)
{
	return &__stack[(STACK_SIZE * init_index) + STACK_SIZE];
}

int platform_range_permitted(uint64_t pstart, size_t len)
{
	int entry = 0, res = 0;
	uint64_t pend = (pstart + len) - 1;

	if (pend <= pstart)
		return res;

	while (noaccess[entry].end) {
		if ((noaccess[entry].start <= pstart) &&
		    (pstart <= noaccess[entry].end))
			break;
		if ((noaccess[entry].start <= pend) &&
		    (pend <= noaccess[entry].end))
			break;
		if ((pstart < noaccess[entry].start) &&
		    (noaccess[entry].end < pend))
			break;
		entry++;
	}

	if (!noaccess[entry].end)
		res = 1;

	return res;
}
