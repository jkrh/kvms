/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __PRODUCT_MMAP_H__
#define __PRODUCT_MMAP_H__

#include <stdint.h>
#include "commondefines.h"

extern uint64_t __HYP_BASE[];
extern uint64_t __HYP_SIZE[];
extern uint64_t __HYP_LIMIT[];
#define HYP_ADDRESS ((uint64_t)__HYP_BASE)
#define HYP_SIZE ((uint64_t)__HYP_SIZE)
#define HYP_END ((uint64_t)__HYP_LIMIT - 1)

/* Physical areas for which hyp will deny mapping requests */
static const struct memrange noaccess[] = {
	{ 0x00000000UL, 0x3FFFFFFFUL }, /* device space */
	{ HYP_ADDRESS, HYP_END },
	{ 0, 0 }
};

#endif /* __PRODUCT_MMAP_H__ */
