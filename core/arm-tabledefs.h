/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM_TABLEDEFS_H__
#define __ARM_TABLEDEFS_H__
/*
 * Reference:
 * Arm Architecture Reference Manual
 * Armv8, for Armv8-A architecture profile
 */

#define MAX_TABLE_LEVELS	4

#define PT_SIZE_WORDS   512

/*
 * Stage-1 S2AP
 *    EL1        EL0
 * 00 Read/write None
 * 01 Read/write Read/write
 * 10 Read-only  None
 * 11 Read-only  Read-only
 *
 * Stage-2 S2AP
 * 00 None
 * 01 Read-only
 * 10 Write-only
 * 11 Read/write
 */

#define PROT_MASK_STAGE1	0x600000000003E0
#define PROT_MASK_STAGE2	0x6A0000000003C0
#define TYPE_MASK_STAGE1	0x1C
#define TYPE_MASK_STAGE2	0x3C
#define ATTR_INDX_SHIFT		2

#define VADDR_MASK		0xFFFFFFFFFFFFUL
#define ATTR_MASK		0xFFFC0000000003FCUL

/*
 * Permissions, stage 1:
 */
#define S1_PXN_SHIFT		53
#define S1_PXN			(1UL << S1_PXN_SHIFT)

#define S1_UXN_SHIFT		54
#define S1_UXN			(1UL << S1_UXN_SHIFT)

#define S1_AP_SHIFT		6
#define S1_AP_MASK		(0x3UL << S1_AP_SHIFT)

#define S1_AP_RW_N		0UL
#define S1_AP_RW_RW		(1UL << S1_AP_SHIFT)
#define S1_AP_RO_N		(2UL << S1_AP_SHIFT)
#define S1_AP_RO_RO		(3UL << S1_AP_SHIFT)

#define PAGE_KERNEL_RW		S1_UXN              //0x40000000000000
#define PAGE_KERNEL_RWX		0x00000000000000
#define PAGE_KERNEL_RO		(S1_UXN | S1_AP_RO_N) //0x40000000000080
#define PAGE_KERNEL_EXEC	S1_AP_RO_N          //0x00000000000080

/* Stage 2 */
#define S2_XN_SHIFT		53
#define S2_XN_MASK		(0x3UL << S2_XN_SHIFT)
#define S2_EXEC_EL1EL0		(0x0UL << S2_XN_SHIFT)
#define S2_EXEC_EL0		(0x1UL << S2_XN_SHIFT)
#define S2_EXEC_NONE		(0x2UL << S2_XN_SHIFT)
#define S2_EXEC_EL1		(0x3UL << S2_XN_SHIFT)

#define S2AP_SHIFT		6
#define S2AP_MASK		(0x3UL << S2AP_SHIFT)
#define S2AP_NONE		(0 << S2AP_SHIFT)
#define S2AP_READ		(1UL << S2AP_SHIFT)
#define S2AP_WRITE		(2UL << S2AP_SHIFT)
#define S2AP_RW			(3UL << S2AP_SHIFT)

#define PAGE_HYP_RW		(S2_EXEC_NONE | S2AP_RW)     //0x400000000000c0
#define PAGE_HYP_RWX		(S2_EXEC_EL1EL0 | S2AP_RW)   //0x000000000000c0
#define PAGE_HYP_RO		(S2_EXEC_NONE | S2AP_READ)   //0x40000000000040
#define PAGE_HYP_EXEC		(S2_EXEC_EL1EL0 | S2AP_READ) //0x00000000000040

#define S2_MEM_ATTR_SHIFT	2
#define S2_MEM_ATTR_MASK	(0x0fUL << S2_MEM_ATTR_SHIFT)
#define S2_MEMTYPE_DEVICE	0

/* Shareability SH [9:8], Stage 1 and 2 */
#define SH_SHIFT		0x8
#define SH_NO			0x0
#define SH_OUT			0x2
#define SH_INN			0x3

#define S2_SH_INN		(SH_INN << SH_SHIFT)

/* Stage 2 MemAttr[3:2] */
#define S2_MEM_ATTR_SHIFT	2
#define S2_MEM_TYPE_SHIFT	(S2_MEM_ATTR_SHIFT + 2)
#define S2_MEM_TYPE_MASK	(0x3 << S2_MEM_TYPE_SHIFT)
#define S2_DEVICE		(0x0 << S2_MEM_TYPE_SHIFT)
#define S2_ONONE		(0x1 << S2_MEM_TYPE_SHIFT)
#define S2_OWT			(0x2 << S2_MEM_TYPE_SHIFT)
#define S2_OWB			(0x3 << S2_MEM_TYPE_SHIFT)

/* Stage 2 MemAttr[1:0] Meaning when MemAttr[3:2] == 0b00 */
#define NGNRNE			(0x0 << S2_MEM_ATTR_SHIFT)
#define NGNRE			(0x1 << S2_MEM_ATTR_SHIFT)
#define NGRE			(0x2 << S2_MEM_ATTR_SHIFT)
#define GRE			(0x3 << S2_MEM_ATTR_SHIFT)

/* Stage 2 MemAttr[1:0] Meaning when MemAttr[3:2] != 0b00 */
/* Inner Non-cacheable */
#define S2_INONE		(0x1 << S2_MEM_ATTR_SHIFT)
/* Inner Write-Through Cacheable */
#define S2_IWT			(0x2 << S2_MEM_ATTR_SHIFT)
/* Inner Write-Back Cacheable */
#define S2_IWB			(0x3 << S2_MEM_ATTR_SHIFT)

/* Stage 2 device memory attributes */
#define S2_DEV_NGNRNE		(S2_DEVICE | NGNRNE)
#define S2_DEV_NGNRE		(S2_DEVICE | NGNRE)
#define S2_DEV_NGRE		(S2_DEVICE | NGRE)
#define S2_DEV_GRE		(S2_DEVICE | GRE)

#define MAX_CONTIGUOUS	128

#endif // __ARM_TABLEDEFS_H__
