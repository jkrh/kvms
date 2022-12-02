// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "lz4.h"
#include "lsymbols.h"

#define wfe() __asm__ __volatile__("wfe\n" : : :);
#define NORETURN __attribute__ ((noreturn))
#define ALIGN(N) __attribute__((aligned(N)))
#define UNUSED __attribute__((unused))
#define PAGE_SIZE 4096

uint8_t __stack[PAGE_SIZE] ALIGN(16);
extern char HYP_BIN_START[];
typedef int hyp_func_t(uint64_t, ...);

NORETURN
void hyp_abort(int res UNUSED)
{
	while (1) wfe();
}

int uncompress_hyp(void *addr)
{
	uint64_t res;

	res = lz4dec((void *)&HYP_BIN_START, addr, HYP_BIN_SIZE);
	if (!res)
		return -EFAULT;

	return 0;
}

int main(void *start_addr, void *extract_addr, uint64_t sp[])
{
	hyp_func_t *hyp_main;
	int res;

	res = uncompress_hyp(extract_addr);
	if (res)
		hyp_abort(res);

	hyp_main = (hyp_func_t *)start_addr;
	res = hyp_main(sp[0], sp[1], sp[2], sp[3], sp[4], sp[5], sp[6], sp[7], sp[8]);

	hyp_abort(res);
}
