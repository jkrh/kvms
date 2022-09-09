#ifndef __HOST_PLATFORM_H__
#define __HOST_PLATFORM_H__

#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

#include "host_defs.h"
#include "arm-sysregs.h"

extern uintptr_t __BL1_RAM_START__;
extern uintptr_t HYP_LIMIT;
extern uintptr_t __RO_START__;

#define STACK_SIZE		0x2000
#define BL1_RAM_BASE		(unsigned long)(&__BL1_RAM_START__)
#define BL1_RAM_LIMIT		(unsigned long)(&HYP_LIMIT)
#define BL_CODE_BASE		(unsigned long)(&__RO_START__)
#define BL_CODE_LIMIT		(unsigned long)(&__BL1_RAM_START__)

#define TABLE_LEVELS    3

/* OPTEE */
#define TEE_SHM_START		0xffc00000
#define TEE_SHM_SIZE		0x400000

#define PLATFORM_SMP_CORE_INDEX	((read_reg(mpidr_el1) & MPIDR_AFF0_MASK) + \
				((read_reg(mpidr_el1) & MPIDR_AFF1_MASK) >> 6))

#endif /*__HOST_PLATFORM_H__*/
