// SPDX-License-Identifier: GPL-2.0-only

#ifndef __KVJMP_H__
#define __KVJMP_H__

#include <stdint.h>

/**
 * Query if given jump is a valid kernel trampoline
 *
 * @param addr
 * @return zero if not, 1 if it is
 */
int is_jump_valid(uint64_t addr);

/**
 * Add address as a legit kernel trampoline
 *
 * @param addr
 * @return zero if address was added, negative error code on failure
 */
int add_jump(uint64_t addr);

#endif
