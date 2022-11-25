/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __PLATFORM_CRYPTO__
#define __PLATFORM_CRYPTO__
#include "mbedconfig.h"
#include "mbedtls/sha256.h"

#ifdef USE_HW_CRYPTO
struct user_fpsimd_state {
	__uint128_t	vregs[32];
	uint32_t	fpsr;
	uint32_t	fpcr;
	uint32_t	__reserved[2];
};

typedef struct {
	struct user_fpsimd_state fpsimd;
	bool cptr_el2_tfp;
} platform_crypto_ctx_t;

void get_platform_crypto_ctx(platform_crypto_ctx_t *store);
void give_platform_crypto_ctx(platform_crypto_ctx_t *store);

#define RESERVE_PLATFORM_CRYPTO(p) get_platform_crypto_ctx(p)
#define RESTORE_PLATFORM_CRYPTO(p) give_platform_crypto_ctx(p)

#else
#define RESERVE_PLATFORM_CRYPTO(p) ((void) p)
#define RESTORE_PLATFORM_CRYPTO(p) ((void) p)

typedef uint32_t platform_crypto_ctx_t; /* dummy definition */

#endif

#endif /*__PLATFORM_CRYPTO__ */
