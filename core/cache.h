/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __CACHE_H__
#define __CACHE_H__

#include <stdint.h>

void __inval_dcache_area(void *addr, size_t sz);
void __flush_dcache_area(void *addr, size_t sz);

#endif
