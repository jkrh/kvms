/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __PRODUCT_MMAP_H__
#define __PRODUCT_MMAP_H__

#include <stdint.h>
#include "commondefines.h"

#define HYP_ADDRESS 0xC0000000UL
#define HYP_SIZE SZ_1M * 256
#define HYP_END HYP_ADDRESS + HYP_SIZE - 1

/* Physical areas for which hyp will deny mapping requests */
static const struct memrange noaccess[] = {
	{ 0x00000000UL, 0x3FFFFFFFUL }, /* device space */
	{ HYP_ADDRESS, HYP_END },
	{ 0, 0 }
};

#endif /* __PRODUCT_MMAP_H__ */
