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

#define STACK_SIZE	PAGE_SIZE * 4

#if TABLE_LEVELS == 4
#define VA_BITS 40
#define VA_WIDTH (64 - VA_BITS)
#define PLATFORM_VTCR_EL2      (0x23580 | VA_WIDTH)
#define PLATFORM_TCR_EL2       0x0
#else
#define PLATFORM_VTCR_EL2	0x1355C
#define PLATFORM_TCR_EL2	0x80813519
#endif

int console_putc(unsigned char);

#endif
