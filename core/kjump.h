// SPDX-License-Identifier: GPL-2.0-only

#ifndef __KVJMP_H__
#define __KVJMP_H__

#include <stdint.h>

#define JUMP_VA_MASK ~0xFFFFFFFFFFF00000UL

/**
 * Query if given jump is a valid kernel trampoline
 *
 * @param addr
 * @return zero if not, 1 if it is
 */
int is_jump_valid(uint64_t addr);

/**
 * Initialize kvm jump trampoline
 *
 * @return void
 */
void init_kvm_vector(void);

#endif
