// SPDX-License-Identifier: GPL-2.0-only

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "ecdsa.h"

#include "mbedtls/platform.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/bignum.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
//#include "signature_pub.h"

#define CHECKRES(x, expected, err_handler) \
		do { \
			if ((x) != (expected)) { \
				goto err_handler; \
			} \
		} while (0)

int do_ecdsa(uint8_t *sign, uint8_t *hash, uint8_t *pub, size_t pub_size)
{
	mbedtls_ecdsa_context ctx;
	mbedtls_ecp_group grp;
	mbedtls_ecp_keypair key;
	int ret;
	int err = -EINVAL;
	uint32_t sign_len;

	if (!sign || !hash || sign[0] != 0x30 || sign[2] != 0x02) {
		return -EINVAL;
	}

	sign_len = sign[1] + 2;
	mbedtls_ecdsa_init(&ctx);
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_keypair_init(&key);
	mbedtls_ecp_point_init(&key.Q);

	ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_ecp_point_read_binary(&grp, &key.Q,
					    pub, pub_size);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_ecp_group_copy(&key.grp, &grp);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_ecdsa_from_keypair(&ctx, &key);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_ecp_check_pubkey(&grp, &key.Q);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_ecdsa_read_signature(&ctx, hash, 32, sign, sign_len);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	err = ret;
err_handler:
	mbedtls_ecp_group_free(&grp);
	mbedtls_ecp_keypair_free(&key);
	mbedtls_ecdsa_free(&ctx);
	return err;
}
