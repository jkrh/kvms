/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __SYS_CONTEXT_H__
#define __SYS_CONTEXT_H__

#include <stdint.h>

typedef struct {
	uint64_t vttbr_el2;
	uint64_t vtcr_el2;
	uint64_t ttbr0_el1;
	uint64_t ttbr1_el1;
	uint64_t hcr_el2;
	uint64_t cptr_el2;
	uint64_t mdcr_el2;
	uint64_t hstr_el2;
} sys_context_t;

#endif // __SYS_CONTEXT_H__
