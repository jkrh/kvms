// SPDX-License-Identifier: GPL-2.0-only
#include "mtree.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform.h"

#define CHECKRES(x) if (x != MBEDTLS_EXIT_SUCCESS) return -EFAULT;
#define CHECKFAULT(x)

int calc_hash(uint8_t hash[32], uint8_t *data, size_t len)
{
	int res;

	res = mbedtls_sha256_ret(data, len, hash, 0);
	CHECKRES(res);

	return 0;
}

int build_mtree(mtree_t *t, uint8_t *data, size_t len)
{
	mbedtls_sha256_context s;
	uint8_t hash1[32];
	uint8_t hash2[32];
	uint8_t *end = data + len;
	uint64_t i, z;
	int res;

	if (!t || !data)
		return -EINVAL;

	if (len % (PAGE_SIZE*2))
		return -EINVAL;

	/* Clean up */
	memset(t, 0, sizeof(*t));

	for (i = 0; i < MAX_MTREE_BLOCKS/2; i+=2) {
		/* Hash datablocks */
		res = calc_hash(hash1, data, PAGE_SIZE);
		CHECKRES(res);
		data += PAGE_SIZE;

		res = calc_hash(hash2, data, PAGE_SIZE);
		CHECKRES(res);
		data += PAGE_SIZE;

		mbedtls_sha256_init(&s);
		res = mbedtls_sha256_starts_ret(&s, 0);
		CHECKRES(res);
		res = mbedtls_sha256_update_ret(&s, hash1, 32);
		CHECKRES(res);
		res = mbedtls_sha256_update_ret(&s, hash2, 32);
		CHECKRES(res);
		res = mbedtls_sha256_finish_ret(&s, t->l2.blocks[i].base_hash);
		CHECKRES(res);

		if (data >= end)
			break;
	}
	z = 0;
	for (i = 0; i < MAX_MTREE_BLOCKS/4; i+=2) {
		mbedtls_sha256_init(&s);
		res = mbedtls_sha256_starts_ret(&s, 0);
		CHECKRES(res);
		res = mbedtls_sha256_update_ret(&s, t->l2.blocks[i].base_hash, 32);
		CHECKRES(res);
		res = mbedtls_sha256_update_ret(&s, t->l2.blocks[i+1].base_hash, 32);
		CHECKRES(res);
		res = mbedtls_sha256_finish_ret(&s, t->l3.blocks[z++].base_hash);
		CHECKRES(res);
	}
	/* Root hash */
	mbedtls_sha256_init(&s);
	res = mbedtls_sha256_starts_ret(&s, 0);
	CHECKRES(res);
	for (i = 0; i < MAX_MTREE_BLOCKS/4; i++) {
		res = mbedtls_sha256_update_ret(&s, t->l3.blocks[i].base_hash, 32);
		CHECKRES(res);
	}
	return mbedtls_sha256_finish_ret(&s, t->l4.block.base_hash);
}

int check_page(mtree_t *t, uint8_t *data)
{
	mbedtls_sha256_context s;
	uint64_t distance, index, l2index, l3index, v;
	uint8_t hash1[32];
	uint8_t hash2[32];
	uint8_t hash3[32];
	int res;

	/* Input data validation */

	if ((uint64_t)data % PAGE_SIZE)
		return -EINVAL;

	if ((data < t->data_base) ||
	    (data > t->data_base + t->data_len))
		return -ENOENT;

	/* Get element page index */

	distance = data - t->data_base;
	if (distance > (MAX_MTREE_BLOCKS * PAGE_SIZE))
		return -EINVAL;

	index = distance / PAGE_SIZE;
	if (index > MAX_MTREE_BLOCKS)
		return -EINVAL;

	v = index % 2;

	/* Calculate the current measurement */

	if (!v) {
		res = calc_hash(hash1, data, PAGE_SIZE);
		CHECKRES(res);
		res = calc_hash(hash2, data + PAGE_SIZE, PAGE_SIZE);
		CHECKRES(res);
	} else {
		res = calc_hash(hash2, data - PAGE_SIZE, PAGE_SIZE);
		CHECKRES(res);
		res = calc_hash(hash1, data, PAGE_SIZE);
		CHECKRES(res);
	}

	/* Verify first level up */

	mbedtls_sha256_init(&s);
	res = mbedtls_sha256_starts_ret(&s, 0);
	CHECKRES(res);
	if (!v) {
		res = mbedtls_sha256_update_ret(&s, hash1, 32);
		CHECKRES(res);
		res = mbedtls_sha256_update_ret(&s, hash2, 32);
		CHECKRES(res);
	} else {
		res = mbedtls_sha256_update_ret(&s, hash2, 32);
		CHECKRES(res);
		res = mbedtls_sha256_update_ret(&s, hash1, 32);
		CHECKRES(res);
	}
	res = mbedtls_sha256_finish_ret(&s, hash3);
	CHECKRES(res);

	l2index = index / 2;
	if (memcmp(hash3, t->l2.blocks[l2index].base_hash, 32))
		return -EPERM;

	/* Second level */

	v = l2index % 2;
	mbedtls_sha256_init(&s);
	res = mbedtls_sha256_starts_ret(&s, 0);
	CHECKRES(res);
	if (!v) {
		res = mbedtls_sha256_update_ret(&s, t->l2.blocks[l2index].base_hash, 32);
		CHECKRES(res);
		res = mbedtls_sha256_update_ret(&s, t->l2.blocks[l2index+1].base_hash, 32);
		CHECKRES(res);
	} else {
		res = mbedtls_sha256_update_ret(&s, t->l2.blocks[l2index-1].base_hash, 32);
		CHECKRES(res);
		res = mbedtls_sha256_update_ret(&s, t->l2.blocks[l2index].base_hash, 32);
		CHECKRES(res);
	}
	res = mbedtls_sha256_finish_ret(&s, hash3);
	CHECKRES(res);

	l3index = l2index / 2;
	if (memcmp(hash3, t->l3.blocks[l3index].base_hash, 32))
		return -EPERM;

	/*
	 * Third level.
	 *
	 * TODO: for large amounts of data this is way too unbalanced and big.
	 * But before fixing that verify what is really the amount of data we
	 * really need to hold.
	 */
	mbedtls_sha256_init(&s);
	res = mbedtls_sha256_starts_ret(&s, 0);
	CHECKRES(res);
	for (v = 0; v < MAX_MTREE_BLOCKS/4; v++) {
		res = mbedtls_sha256_update_ret(&s, t->l3.blocks[v].base_hash, 32);
		CHECKRES(res);
	}
	res = mbedtls_sha256_finish_ret(&s, hash3);
	CHECKRES(res);

	/* Root hash validation */

	if (memcmp(hash3, t->l4.block.base_hash, 32))
		return -EPERM;

	return 0;
}
