/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __PLATFORM_CRYPTO__
#define __PLATFORM_CRYPTO__
#include "mbedconfig.h"
#include "mbedtls/sha256.h"

typedef struct {
	__uint128_t q0_q31[32];
} simd_t;

extern void store_simd(simd_t *store);
extern void restore_simd(simd_t *store);

#ifdef MBEDTLS_SHA256_PROCESS_ALT
#define RESERVE_PLATFORM_CRYPTO(p) store_simd(p)
#define RESTORE_PLATFORM_CRYPTO(p) restore_simd(p)
#else
#define RESERVE_PLATFORM_CRYPTO(p) ((void) p)
#define RESTORE_PLATFORM_CRYPTO(p) ((void) p)
#endif
#endif /*__PLATFORM_CRYPTO__ */
