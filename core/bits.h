/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __BITS_H__
#define __BITS_H__

#include <stdint.h>

#define bit_t(x) x
#define bit_to_mask(x) (0x1UL << ((x) & 63UL))
#define bit_set(c, flag) (bit_t(c) |= bit_to_mask(flag))
#define bit_drop(c, flag) (bit_t(c) &= ~bit_to_mask(flag))
#define bit_raised(c, flag) (bit_t(c) & bit_to_mask(flag))

#define VALID_TABLE_BIT 0
#define TABLE_TYPE_BIT  1
#define NSTABLE_BIT     63

/* For block and page entries, stage 1 and 2 */
#define PTE_SHARED 49 /* Res0: our magic marker */
#define DBM_BIT 51
#define CONTIGUOUS_BIT 52
#define PXN_BIT 53
#define XN_BIT 54
#define NS_BIT 5
#define AP1_BIT 6
#define AP2_BIT 7
#define SH1_BIT 8
#define SH2_BIT 9
#define AF_BIT 10

/* HCR */
#define HCR_VM_BIT 0
#define HCR_FB_BIT 9
#define HCR_TWI_BIT 13
#define HCR_TWE_BIT 14
#define HCR_TSC_BIT 19
#define HCR_TVM_BIT 26
#define HCR_RW_BIT 31
#define HCR_NV_BIT 40
#define HCR_NV1_BIT 43
#define HCR_NV2_BIT 45

/* CPTR */
#define CPTR_TCPAC_BIT 31
#define CPTR_TTA_BIT 28
#define CPTR_TFP_BIT 10

/* CNTHCTL */
#define CNTHCTL_EL1PCTEN_BIT 0
#define CNTHCTL_EL1PCEN_BIT 1
#define CNTHCTL_ENVTEN_BIT 2

/* SCTLR */
#define SCTLR_MMU 0
#define SCTLR_A 1
#define SCTLR_C 2
#define SCTLR_NAA 6

/* VTCR */
#define VTCR_IRGN0_BIT1 8
#define VTCR_IRGN0_BIT2 9
#define VTCR_ORGN0_BIT1 10
#define VTCR_ORGN0_BIT2 11
#define VTCR_SH0_BIT1 12
#define VTCR_SH0_BIT2 13
#define VTCR_HA_BIT 21
#define VTCR_HD_BIT 22
#define VTCR_NSW_BIT 29

#endif
