#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "armtrans.h"
#include "helpers.h"
#include "host_platform.h"
#include "hyplogs.h"
#include "bits.h"
#include "guest.h"
#include "hvccall.h"
#include "validate.h"
#include "tables.h"
#include "gic.h"

#define UART01x_FR_BUSY 0x008
#define UART01x_FR 0x18 /* Flag register (Read only). */
#define UART01x_DR 0x00 /* Data read or written from the interface. */
#define UART01x_RSR 0x04 /* Receive status register (Read). */

uint8_t __stack[STACK_SIZE * PLATFORM_CORE_COUNT] ALIGN(16) DATA;

int _IO_putc (int c, FILE *fp);

static bool init_ready;

typedef struct {
	uint64_t addr;
	uint64_t len;
} memmap;

static const memmap base_memmap[] = {
	{ 0, 0x08000000UL },
	{ GIC_DIST_ADDR, GIC_DIST_SZ },
	{ 0x08010000UL, 0x00010000UL },
	{ 0x08020000UL, 0x00001000UL },
	{ 0x08030000UL, 0x00010000UL },
	{ 0x08040000UL, 0x00010000UL },
	{ 0x08080000UL, 0x00020000UL },
	{ 0x080A0000UL, 0x00F60000UL },
	{ VIRT_UART, 0x00001000UL },
	{ 0x09010000UL, 0x00001000UL },
	{ 0x09020000UL, 0x00001000UL },
	{ 0x09030000UL, 0x00001000UL },
	{ 0x09040000UL, 0x00001000UL },
	{ 0x09050000UL, 0x00020000UL },
	{ 0x09070000UL, 0x00001000UL },
	{ 0x09080000UL, 0x00001000UL },
	{ 0x0a000000UL, 0x00004000UL },
	{ 0x0c000000UL, 0x02000000UL },
	{ 0x0e000000UL, 0x01000000UL },
	{ 0x10000000UL, 0x2eff0000UL },
	{ 0x3eff0000UL, 0x00010000UL },
	{ 0x3f000000UL, 0x01000000UL },
	{ 0, 0 },
};

typedef struct {
	uint64_t start;
	uint64_t end;
} memrange;

/* Physical areas for which hyp will deny mapping requests */
static const memrange noaccess[] = {
	{  0x00000000UL,  0x3FFFFFFFUL },
	{ 0x100000000UL, 0x13FFFFFFFUL },
	{ 0, 0 }
};

void platform_init_slots(kvm_guest_t *host)
{
	/*
	 * Placeholder.
	 */
	host->slots[0].slot.base_gfn = 0;
	host->slots[0].slot.npages = (KERNEL_BASE + KERN_VA_MASK) >> PAGE_SHIFT;
}

int machine_virt(kvm_guest_t *host)
{
	int stage = EL2_STAGE1, res = 0, i;
	uint64_t perms, type;

	host->s2_host_access = true;

nextmap:
	i = 0;
	while (base_memmap[i].len) {
		if (stage == STAGE2) {
			perms = ((SH_INN<<8) | PAGE_HYP_RW);
			type = S2_DEV_NGNRE;
		} else {
			perms = PAGE_KERNEL_RW;
			type = DEVICE_MEMORY;
		}

		res = mmap_range(host, stage, base_memmap[i].addr,
				 base_memmap[i].addr, base_memmap[i].len,
				 perms, type);
		if (res)
			goto error;
		i++;
	}
	if (stage == EL2_STAGE1) {
		stage = STAGE2;
		goto nextmap;
	}
	perms = PAGE_KERNEL_RWX;
	res = mmap_range(host, EL2_STAGE1, PHYS_OFFSET, PHYS_OFFSET,
			 SZ_1G * 4, perms, NORMAL_MEMORY);
	if (res)
		goto error;

	perms = ((SH_INN<<8) | PAGE_HYP_RWX);
	res = mmap_range(host, STAGE2, PHYS_OFFSET, PHYS_OFFSET,
			 SZ_1G * 3, perms, S2_NORMAL_MEMORY);
	if (res)
		goto error;

	host->table_levels_s2 = TABLE_LEVELS;
	host->table_levels_s1 = TABLE_LEVELS;
	host->ramend = 0x200000000UL;

	/* Initial slots for host */
	platform_init_slots(host);

	/* Virt is a debug target, dump. */
	print_mappings_el2();
	print_mappings(HOST_VMID, STAGE2);

error:
	LOG("virt initialization return: %x\n\n", res);
	return res;
}

#ifdef DEBUG
int _IO_putc(int c, struct _IO_FILE *__fp)
{
	uint8_t *uart = (uint8_t *)VIRT_UART;

	*(uart + UART01x_DR) = c;
	while (*(uart + UART01x_FR) & UART01x_FR_BUSY) {
	}

	return 0;
}
#endif

int console_putc(unsigned char c)
{
	return _IO_putc((int)c, NULL);
}

int machine_init(kvm_guest_t *host)
{
	int res;

	init_ready = false;
	res = machine_virt(host);
	init_ready = true;

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
		HYP_ABORT();

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

	if (next_vmid < GUEST_VMID_START)
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

void platform_console_init(void)
{
	/* placeholder */
}

uint8_t *platfrom_get_stack_ptr(uint64_t init_index)
{
	return &__stack[(STACK_SIZE * init_index) + STACK_SIZE];
}

int platform_range_permitted(uint64_t pstart, size_t len)
{
	int entry = 0, res = 0;
	uint64_t pend = (pstart + len) - 1;

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
