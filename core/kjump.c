#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>

#include "spinlock.h"
#include "kjump.h"
#include "mm.h"

#ifndef MAX_KVM_JUMPS
#define MAX_KVM_JUMPS 16
#endif

static uint64_t kvm_jump_vector[MAX_KVM_JUMPS];
static uint32_t jump_count;
static uint64_t jump_lock;

static int compfunc(const void *v1, const void *v2)
{
	uint64_t val1 = (uint64_t)*(uint64_t *)v1;
	uint64_t val2 = (uint64_t)*(uint64_t *)v2;

	return (val1 - val2);
}

int is_jump_valid(uint64_t addr)
{
	uint64_t key = addr;
	void *res;

	res = bsearch((void *)&key, kvm_jump_vector, jump_count,
		      sizeof(uint64_t), compfunc);
	if (res)
		return 1;

	return 0;
}

int add_jump(uint64_t addr)
{
	if (jump_count > MAX_KVM_JUMPS)
		return -ENOSPC;

	spin_lock(&jump_lock);
	if (is_jump_valid(addr))
		goto out;

	kvm_jump_vector[jump_count] = addr;
	jump_count++;
	qsort(kvm_jump_vector, jump_count, sizeof(uint64_t),
	      compfunc);
out:
	spin_unlock(&jump_lock);

	return 0;
}
