/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __PRODUCT_MMAP_H__
#define __PRODUCT_MMAP_H__

#include <stdint.h>

/* EL2 (stage 1 only) translation table. Add here any custom mappings that needs to be accessible from EL2 */
static const memmap base_memmap[] = {
	/* VA start,  VA end,     IPA start,  Region size,   Memory type, Shared,      R/W/exec*/
	/* DDR */
	{ 0x880000000, 0x8BFFFFFFF, 0x880000000, 0x40000000, NORMAL_WBACK_P, SH_OUT, PAGE_KERNEL_RW }, /* 1GB DDR Main memory */
	/* DDR */
	{ 0x80000000, 0xFFFFFFFF, 0x80000000, 0x80000000, NORMAL_WBACK_P, SH_OUT, PAGE_KERNEL_RW }, /* 2GB DDR Main memory */
	/* GIC Distributor */
	{ 0x51a00000, 0x51a0FFFF, 0x51a00000, 0x10000, DEVICE_MEMORY, SH_NO, PAGE_KERNEL_RW }, /* 64kB GIC Distributor */
	/* DMA.LPUART0 (UART0) */
	{ 0x5A060000, 0x5A06FFFF, 0x5A060000, 0x10000, DEVICE_MEMORY, SH_NO, PAGE_KERNEL_RW }, /* 64kB DMA.LPUART0 */
	{ 0, 0, 0, 0, 0 }
};

/* EL2 (stage 1 only) translation table. Add here any custom mappings that needs to be accessible from EL2 in secure boot */
static const memmap el2_secure_memmap[] = {
	/*          VA start,             VA end,           PA start, Block size,   Memory type, Shared,      R/W/exec*/
	/* Example: */
	/*{ 0x00000000BFD00000, 0x00000000BFFFFFFF, 0x00000000BFD00000, 0x00001000, NORMAL_WT_P, SH_INN, PAGE_KERNEL_RW },*/
	{ 0, 0, 0, 0, 0 }
};

/*
 * Stage 2 translation table. Stage 2 host mappings
 *
 * Reference:
 * i.MX 8QuadXPlus Applications Processor Reference Manual, Rev. 0, 05/2020
 * Table 2-2. System memory map
 *
 * Total DDR size (3Gb) can be found at link below
 * https://www.nxp.com/design/development-boards/i-mx-evaluation-and-development-boards/i-mx-8quadxplus-multisensory-enablement-kit-mek:MCIMX8QXP-CPU
 *
 */
static const memmap st2_base_memmap[] = {
	/* IPA start,  IPA end,     PA start,    Region size, Memory type, Shared, R/W/exec*/
	/* DDR */
	{ 0x880000000, 0x8BFFFFFFF, 0x880000000, 0x40000000, S2_NORMAL_MEMORY, SH_INN, PAGE_HYP_RWX }, /* 1GB DDR Main memory */
	/* Reserved */
	/* { 0x800000000, 0x87FFFFFFF, 0x800000000, 0x80000000, type, sh, exec },  Reserved - 2GB DRAM Hole */
	/* Reserved */
	/* { 0x440000000, 0x7FFFFFFFF, 0x440000000, 0x3C0000000, type, sh, exec },  15GB Reserved - Mapped I/O */
	/* LSIO */
	{ 0x400000000, 0x43FFFFFFF, 0x400000000, 0x40000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 1GB FlexSPI1 + Other */
	/* Reserved */
	/* { 0x100000000, 0x3FFFFFFFF, 0x100000000, 0x300000000, type, sh, exec },  12GB Reserved */
	/* DDR */
	{ 0x80000000, 0xFFFFFFFF, 0x80000000, 0x80000000, S2_NORMAL_MEMORY, SH_INN, PAGE_HYP_RWX }, /* 2GB DDR Main memory */
	/* HSIO */
	{ 0x70000000, 0x7FFFFFFF, 0x70000000, 0x10000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 256MB PCIe */
	/* Reserved */
	/* { 0x60000000, 0x6FFFFFFF, 0x60000000, 0x10000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, */ /* 256MB Reserved */
	/* HSIO */
	{ 0x5F000000, 0x5FFFFFFF, 0x5F000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 16MB High Speed I/O */
	/* Reserved */
	/* { 0x5E000000, 0x5EFFFFFF, 0x5E000000, 0x1000000, type, sh, exec },  16MB Reserved */
	/* LSIO */
	{ 0x5D000000, 0x5DFFFFFF, 0x5D000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 16MB Low Speed I/O */
	/* Db */
	{ 0x5C000000, 0x5CFFFFFF, 0x5C000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 16MB Db */
	/* Conn */
	{ 0x5B000000, 0x5BFFFFFF, 0x5B000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 16MB Connectivity */
	/* DMA */
	{ 0x5A000000, 0x5AFFFFFF, 0x5A000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 16MB DMA */
	/* Audio */
	{ 0x59000000, 0x59FFFFFF, 0x59000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 16MB Audio */
	/* Imaging */
	{ 0x58000000, 0x58FFFFFF, 0x58000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 16MB Imaging Subsystem */
	/* Reserved */
	/* { 0x57000000, 0x57FFFFFF, 0x57000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, */ /* 16MB Reserved */
	/* DC0 */
	{ 0x56000000, 0x56FFFFFF, 0x56000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 16MB Display Controller 0 */
	/* Reserved */
	/* { 0x55000000, 0x55FFFFFF, 0x55000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, */ /* 16MB Reserved */
	/* Reserved */
	/* { 0x54000000, 0x54FFFFFF, 0x54000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, */ /* 16MB Reserved */
	/* GPU0 */
	{ 0x53000000, 0x53FFFFFF, 0x53000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 16MB Graphics 0 */
	/* Reserved */
	/* { 0x52000000, 0x52FFFFFF, 0x52000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, */ /* 16MB Reserved */
	/* DBLOG */
	{ 0x51000000, 0x51FFFFFF, 0x51000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 16MB Audio DMA. DB Logic */
	/* Reserved */
	/* { 0x42000000, 0x50FFFFFF, 0x42000000, 0xF000000, type, sh, exec },  240MB Reserved */
	/* Reserved */
	/* { 0x40000000, 0x41FFFFFF, 0x40000000, 0x2000000, type, sh, exec },  32MB Reserved */
	/* Reserved */
	/* { 0x3C000000, 0x3FFFFFFF, 0x3C000000, 0x4000000, type, sh, exec },  64MB Reserved */
	/* Reserved  */
	/* { 0x38000000, 0x3BFFFFFF, 0x38000000, 0x4000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, */ /* 64MB Reserved */
	/* CM4-0 */
	{ 0x34000000, 0x37FFFFFF, 0x34000000, 0x4000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 64MB Cortex M4 Platform 0 */
	/* SCU */
	{ 0x30000000, 0x33FFFFFF, 0x30000000, 0x4000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 64MB System Control General */
	/* VPU */
	{ 0x2C000000, 0x2FFFFFFF, 0x2C000000, 0x4000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 64MB Video Processing Unit */
	/* Reserved */
	/* { 0x1A000000, 0x2BFFFFFF, 0x1A000000, 0x4000000, type, sh, exec },  64MB Reserved */
    /* LSIO */
	{ 0x19000000, 0x19FFFFFF, 0x19000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 16MB FlexSPI #1 IP TX buffers */
    /* LSIO */
	 { 0x18000000, 0x18FFFFFF, 0x18000000, 0x1000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW },  /* 16MB FlexSPI #1 IP RX buffers */
	/* LSIO */
	{ 0x08000000, 0x17FFFFFF, 0x08000000, 0x10000000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW }, /* 256MB FlexSPI #0 */
	/* Reserved */
	/* { 0x02000000, 0x07FFFFFF, 0x02000000, 0x6000000, type, sh, exec },  96MB Reserved */
	/* Reserved */
	/* { 0x00140000, 0x01FFFFFF, 0x00140000, 0x1EC0000, type, sh, exec },  31488KB Reserved */
	/* LSIO */
	{ 0x00100000, 0x0013FFFF, 0x00100000, 0x40000, S2_NORMAL_MEMORY, SH_INN, PAGE_HYP_RW }, /* 256KB OCRAM */
	/* Reserved */
	/* { 0x00018000, 0x000FFFFF, 0x00018000, 0xE8000, type, sh, exec },  928KB Reserved */
	/* LSIO */
	{ 0x00000000, 0x00017FFF, 0x00000000, 0x18000, S2_NORMAL_MEMORY, SH_INN, PAGE_HYP_RW }, /* 96KB OCRAM alias (lower 96KB) */
	{ 0, 0, 0, 0, 0 }
};

/* Stage 2 translation table. Add here any custom stage 2 host mappings for secure boot */
static const memmap st2_secure_memmap[] = {
	/*          VA start,             VA end,           PA start, Block size,   Memory type, Shared,      R/W/exec*/
	/* Example: */
	/*{ 0x0000000003DA0000, 0x0000000003DA1FFF, 0x0000000003DA0000, 0x00001000, S2_DEV_NGNRE, SH_NO, PAGE_HYP_RW },*/
	{ 0, 0, 0, 0, 0 }
};

/* Physical areas for which hyp will deny mapping requests */
static const struct memrange noaccess[] = {
	/*          PA start,             PA end*/
	/* Example: */
	/*{ 0x0000000000000000, 0x0000000040000000},*/
	{ 0xE0000000, 0xE2FFFFFF },
	{ 0, 0 }
};

#endif /* __PRODUCT_MMAP_H__ */