// SPDX-License-Identifier: GPL-2.0-only

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>

#include "spinlock.h"
#include "kjump.h"
#include "hyplogs.h"
#include "mm.h"

#include "kvmsyms.h"

bool apiwarned = false;

static int compfunc(const void *v1, const void *v2)
{
	uint64_t val1 = *(uint64_t *)v1;
	uint64_t val2 = *(uint64_t *)v2;

	if (val1 < val2)
		return -1;
	if (val1 > val2)
		return 1;
	return 0;
}

static inline void apiwarn(uint64_t addr)
{
	static DEFINE_SPINLOCK(plock);

	spin_lock(&plock);
	ERROR("the kvm jump 0x%lx is not valid, is hyp up to date?\n",
	      addr);
	apiwarned = true;
	spin_unlock(&plock);
}

int is_jump_valid(uint64_t addr)
{
	uint64_t key = addr & JUMP_VA_MASK;
	void *res = NULL;

#ifndef DEBUG
	res = bsearch(&key, kvm_jump_vector, jump_count,
		      sizeof(uint64_t), compfunc);
	if (res)
		return 1;

	apiwarn(addr);
	return 0;
#else
	/*
	 * If it's a debug build and we have already complained about the
	 * ABI inconsistency, just be happy.
	 */
	if (apiwarned)
		return 1;

	res = bsearch(&key, kvm_jump_vector, jump_count,
		      sizeof(uint64_t), compfunc);
	if (res)
		return 1;

	apiwarn(addr);
	return 1;
#endif
}

void init_kvm_vector(void)
{
	for (int i=0; i < jump_count; i++)
		kvm_jump_vector[i] &= JUMP_VA_MASK;

	qsort(kvm_jump_vector, jump_count, sizeof(uint64_t), compfunc);
}
