/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __PRODUCT_MMAP_H__
#define __PRODUCT_MMAP_H__

#include <stdint.h>

/* Physical areas for which hyp will deny mapping requests */
static const struct memrange noaccess[] = {
	{  0x00000000UL,  0x3FFFFFFFUL },
	{ 0x100000000UL, 0x13FFFFFFFUL },
	{ 0, 0 }
};

#endif /* __PRODUCT_MMAP_H__ */
