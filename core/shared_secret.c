// SPDX-License-Identifier: GPL-2.0-only

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "guest.h"
#include "helpers.h"
#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "encryption_priv.h"

#define CHECKRES(x, expected, err_handler) \
		do { \
			if ((x) != (expected)) { \
				goto err_handler; \
			} \
		} while (0)

int derive_key(uint8_t *key, size_t size, uint8_t *salt, size_t salt_size,
		uint8_t *peer_key, size_t peer_size,
		uint8_t *priv_key, size_t priv_size)
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_keypair keypair;
	mbedtls_md_handle_t md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	uint8_t shared_secret[32];
	mbedtls_mpi priv;
	mbedtls_mpi ss_mpi;
	int ret;

	int err = -EINVAL;

	if (!key || !peer_key || !priv_key) {
		return -EINVAL;
	}

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_keypair_init(&keypair);
	mbedtls_ecp_point_init(&keypair.Q);
	mbedtls_mpi_init(&priv);
	mbedtls_mpi_init(&ss_mpi);

	ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	ret = mbedtls_ecp_point_read_binary(&grp, &keypair.Q, peer_key, peer_size);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	mbedtls_mpi_read_binary(&priv, priv_key, priv_size);
	ret= mbedtls_ecdh_compute_shared(&grp, &ss_mpi,
					 &keypair.Q, &priv, NULL, NULL);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	ret = mbedtls_mpi_write_binary(&ss_mpi, shared_secret, sizeof(shared_secret));
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	if (salt_size == 0)
		salt = NULL;

	ret = mbedtls_hkdf(md, salt, salt_size,
			  shared_secret, sizeof(shared_secret),
			  NULL, 0,
			  key, size);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	err = 0;

err_handler:
	memset(shared_secret, 0, sizeof(shared_secret));
	mbedtls_ecp_group_free(&grp);
	mbedtls_ecp_keypair_free(&keypair);
	mbedtls_mpi_free(&priv);
	mbedtls_mpi_free(&ss_mpi);
	return err;
}

int  get_derived_key(kvm_guest_t *guest, void *key, size_t key_size,
		     const void *salt, size_t salt_size)
{
	int ret;

	void *keybuf = malloc(sizeof(gad_t));
	if (!keybuf) {
		ERROR("No memory\n");
		return KIC_ERROR;
	}
	void *saltbuf = malloc(sizeof(gad_t));
	if (!saltbuf) {
		ERROR("No memory\n");
		return KIC_ERROR;
	}

	copy_from_guest(guest, STAGEA, saltbuf, salt, salt_size);
	ret = derive_key(keybuf, key_size, saltbuf, salt_size,
			guest->pubkey, guest->pubkey_size,
			(uint8_t *)&encryption_priv, sizeof(encryption_priv));

	copy_to_guest(guest, STAGEA, key, keybuf, key_size);

	return ret;
}
