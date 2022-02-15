/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __HVCCALL_H__
#define __HVCCALL_H__

#include "hvccall-defines.h"

#define HYP_ABORT() hyp_abort(__func__, __FILE__, __LINE__)

void hyp_abort(const char *func, const char *file, int line);

/**
 * Print registers at address
 *
 * @param regs, the register array
 */
void print_regs(void *regs);

/**
 * Crash function, called from the trap handler in ventry.S
 *
 * @param level, the execution level crash occurred on
 * @param sp, the pt_regs structure location
 * @return void
 */
void dump_state(uint64_t level, void *sp);

/**
 * Set hypervisor lock flags, see above for supported locks.
 *
 * @param flags, the lock flags. See the definitions above.
 * @param vaddr, if applicable for the given lock
 * @param sz, if applicable for the given lock
 * @param depth, if applicable for the given lock
 * @return zero on success or negative error code on failure
 */
int set_lockflags(uint64_t flags, uint64_t vaddr, size_t sz, uint64_t depth);

#endif
