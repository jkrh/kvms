/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LZ4_H__
#define __LZ4_H__

#include <stdint.h>

#ifdef UNSAFE_LZ4
uint64_t lz4dec(const void *src, void *dst, uint64_t srcsz);
#else
uint64_t lz4dec(const void *src, void *dst, uint64_t srcsz, uint64_t dstsz);
#endif

#endif
