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
#include "product_mmap.h"

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
} virt_memmap;

static const virt_memmap base_memmap[] = {
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
			/* Skip flash area from EL2 */
			if (i == 0)
				goto cont;
			perms = PAGE_KERNEL_RW;
			type = DEVICE_MEMORY;
		}

		res = mmap_range(host, stage, base_memmap[i].addr,
				 base_memmap[i].addr, base_memmap[i].len,
				 perms, type);
		if (res)
			goto error;
cont:
		i++;
	}
	if (stage == EL2_STAGE1) {
		stage = STAGE2;
		goto nextmap;
	}
	/* Host ram, HYP */
	perms = PAGE_KERNEL_RWX;
	res = mmap_range(host, EL2_STAGE1, PHYS_OFFSET, PHYS_OFFSET,
			 SZ_1G * 4, perms, NORMAL_MEMORY);
	if (res)
		goto error;

	/* Host ram, Linux */
	perms = ((SH_INN << 8) | PAGE_HYP_RWX);
	res = mmap_range(host, STAGE2, PHYS_OFFSET, PHYS_OFFSET,
			 SZ_1G * 3, perms, S2_NORMAL_MEMORY);
	if (res)
		goto error;

	/* Higmmem area, Linux */
	perms = ((SH_INN << 8) | PAGE_HYP_RW);
	res = mmap_range(host, STAGE2, PCI_HIGHMEM_1, PCI_HIGHMEM_1,
			 SZ_1M * 2, perms, S2_DEV_NGNRE);
	if (res)
		goto error;
	res = mmap_range(host, STAGE2, PCI_HIGHMEM_2, PCI_HIGHMEM_2,
			 SZ_1M * 2, perms, S2_DEV_NGNRE);
	if (res)
		goto error;

	/* Initial slots for host */
	platform_init_slots(host);

	/* Virt is a debug target, dump. */
	print_mappings_el2();
	print_mappings(HOST_VMID, STAGE2);

	platform_init_denyrange();

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

static int set_table_levels(kvm_guest_t *host)
{
	uint64_t vtcr_el2, t0sz;

	vtcr_el2 = PLATFORM_VTCR_EL2;

	switch (VTCR_GET_GRANULE_SIZE(vtcr_el2)) {
	case GRANULE_SIZE_4KB:
		switch (VTCR_SL0(vtcr_el2)) {
		case 0:
			host->table_levels_el1s2 = 2;
			break;
		case 1:
			host->table_levels_el1s2 = 3;
			break;
		case 2:
			host->table_levels_el1s2 = 4;
			break;
		default:
			return -ENOTSUP;
		}
		break;
	/* We only support 4kB granule for now. Flow through */
	case GRANULE_SIZE_16KB:
	case GRANULE_SIZE_64KB:
	default:
		return -ENOTSUP;
	}
	t0sz = TCR_ELx_T0SZ(PLATFORM_TCR_EL2);
	host->table_levels_el2s1 = s1_t0sz_to_levels(t0sz);

	if (host->table_levels_el2s1 == 0)
		return -ENOTSUP;

	return 0;
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

int platform_init_host_pgd(kvm_guest_t *host)
{
	int res;

	if (!host)
		return -EINVAL;

	host->EL2S1_pgd = alloc_pgd(host, &host->el2_tablepool);
	host->EL1S2_pgd = alloc_pgd(host, &host->s2_tablepool);

	if (!host->EL2S1_pgd || !host->EL1S2_pgd)
		return -ENOMEM;

	res = set_table_levels(host);
	if (res)
		return res;

	host->ramend = 0x200000000UL;
	return 0;
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
