// SPDX-License-Identifier: GPL-2.0-only
#include "mtree.h"
#include "constants.h"
#include "sha256.h"

#define CHECKRES(x) if (x < 0) return x;
#define CHECKFAULT(x) if (x == TC_CRYPTO_FAIL) return -EFAULT;

int calc_hash(uint8_t hash[32], uint8_t *data, size_t len)
{
	struct tc_sha256_state_struct s;
	int res;

	res = tc_sha256_init(&s);
	CHECKFAULT(res);

	res = tc_sha256_update(&s, data, len);
	CHECKFAULT(res);

	res = tc_sha256_final(hash, &s);
	CHECKFAULT(res);

	return 0;
}

int build_mtree(mtree_t *t, uint8_t *data, size_t len)
{
	struct tc_sha256_state_struct s;
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

		res = tc_sha256_init(&s);
		CHECKFAULT(res);

		res = tc_sha256_update(&s, hash1, 32);
		CHECKFAULT(res);

		res = tc_sha256_update(&s, hash2, 32);
		CHECKFAULT(res);

		res = tc_sha256_final(t->l2.blocks[i].base_hash, &s);
		CHECKFAULT(res);

		if (data >= end)
			break;
	}
	z = 0;
	for (i = 0; i < MAX_MTREE_BLOCKS/4; i+=2) {
		res = tc_sha256_init(&s);
		CHECKFAULT(res);

		res = tc_sha256_update(&s, t->l2.blocks[i].base_hash, 32);
		CHECKFAULT(res);

		res = tc_sha256_update(&s, t->l2.blocks[i+1].base_hash, 32);
		CHECKFAULT(res);

		res = tc_sha256_final(t->l3.blocks[z++].base_hash, &s);
		CHECKFAULT(res);
	}
	/* Root hash */
	res = tc_sha256_init(&s);
	CHECKFAULT(res);
	for (i = 0; i < MAX_MTREE_BLOCKS/4; i++) {
		res = tc_sha256_update(&s, t->l3.blocks[i].base_hash, 32);
		CHECKFAULT(res);
	}
	res = tc_sha256_final(t->l4.block.base_hash, &s);
	CHECKFAULT(res);

	return 0;
}

int check_page(mtree_t *t, uint8_t *data)
{
	struct tc_sha256_state_struct s;
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

	res = tc_sha256_init(&s);
	CHECKFAULT(res);
	if (!v) {
		res = tc_sha256_update(&s, hash1, 32);
		CHECKFAULT(res);
		res = tc_sha256_update(&s, hash2, 32);
		CHECKFAULT(res);
	} else {
		res = tc_sha256_update(&s, hash2, 32);
		CHECKFAULT(res);
		res = tc_sha256_update(&s, hash1, 32);
		CHECKFAULT(res);
	}
	res = tc_sha256_final(hash3, &s);
	CHECKFAULT(res);

	l2index = index / 2;
	if (memcmp(hash3, t->l2.blocks[l2index].base_hash, 32))
		return -EPERM;

	/* Second level */

	v = l2index % 2;
	res = tc_sha256_init(&s);
	CHECKFAULT(res);
	if (!v) {
		res = tc_sha256_update(&s, t->l2.blocks[l2index].base_hash, 32);
		CHECKFAULT(res);
		res = tc_sha256_update(&s, t->l2.blocks[l2index+1].base_hash, 32);
		CHECKFAULT(res);
	} else {
		res = tc_sha256_update(&s, t->l2.blocks[l2index-1].base_hash, 32);
		CHECKFAULT(res);
		res = tc_sha256_update(&s, t->l2.blocks[l2index].base_hash, 32);
		CHECKFAULT(res);
	}
	res = tc_sha256_final(hash3, &s);
	CHECKFAULT(res);

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

	res = tc_sha256_init(&s);
	CHECKFAULT(res);
	for (v = 0; v < MAX_MTREE_BLOCKS/4; v++) {
		res = tc_sha256_update(&s, t->l3.blocks[v].base_hash, 32);
		CHECKFAULT(res);
	}
	res = tc_sha256_final(hash3, &s);
	CHECKFAULT(res);

	/* Root hash validation */

	if (memcmp(hash3, t->l4.block.base_hash, 32))
		return -EPERM;

	return 0;
}
