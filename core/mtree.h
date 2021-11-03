/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __MTREE_H__
#define __MTREE_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "commondefines.h"

/*
 * Each block can describe a page, so 32768 * 4096 byte max for now.
 */
#define MAX_MTREE_BLOCKS 32768

/* <------------------------------------------------------> l4 hash   (root) */
/* <--------------------------><--------------------------> l3 hashes        */
/* <------------><------------><------------><------------> l2 hashes        */
/* <-----><-----><-----><-----><-----><-----><-----><-----> l1 hashes (data) */

typedef struct {
	uint8_t base_hash[32];
} datablock_t;

typedef struct {
	datablock_t block;
} mtree_l4_t;

typedef struct {
	datablock_t blocks[MAX_MTREE_BLOCKS/4];
} mtree_l3_t;

typedef struct {
	datablock_t blocks[MAX_MTREE_BLOCKS/2];
} mtree_l2_t;

typedef struct {
	uint8_t *data_base;
	size_t data_len;
	mtree_l4_t l4;
	mtree_l3_t l3;
	mtree_l2_t l2;
} mtree_t;

int calc_hash(uint8_t hash[32], uint8_t *data, size_t len);
int build_mtree(mtree_t *t, uint8_t *data, size_t len);
int check_page(mtree_t *t, uint8_t *data);

#endif
