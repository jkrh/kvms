#ifndef __HOST_PLATFORM_H__
#define __HOST_PLATFORM_H__

#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

#include "host_defs.h"
#include "include/generated/uapi/linux/version.h"
#include "platform_api.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#define TABLE_LEVELS    4
#define KVM_ARCH_VMID_OFFT (sizeof(uint64_t))
#else
#define TABLE_LEVELS    3
#endif

#if TABLE_LEVELS == 4
#define VA_BITS 40
#define VA_WIDTH (64 - VA_BITS)
#define PLATFORM_VTCR_EL2      (0x623580 | VA_WIDTH)
#define PLATFORM_TCR_EL2       0x0
#else
#define PLATFORM_VTCR_EL2	0x61355C
#define PLATFORM_TCR_EL2	0x80813519
#endif

/*
 * 0: device_sorder
 * 1: device_order
 * 2: device_gre
 * 3: normal, outer/inner no-cache
 * 4: normal, wback persistent
 * 5: normal, wthrough persistent
 * 6: --
 * 7: --
 */
#define PLAT_DEVICE_STRONGORDER 0
#define PLAT_DEVICE_ORDER 1
#define PLAT_DEVICE_GRE 2
#define PLAT_NORMAL_NOCACHE 3
#define PLAT_NORMAL_WBACK_P 4
#define PLAT_NORMAL_WT_P 5

#define PLATFORM_MAIR_EL2 0x0000bbff440c0400

int console_putc(unsigned char);

#endif
