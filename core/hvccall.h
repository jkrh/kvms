/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __HVCCALL_H__
#define __HVCCALL_H__

#include "hvccall-defines.h"

#define HOST_STAGE1_LOCK	0x1
#define HOST_STAGE2_LOCK	0x2
#define HOST_KVM_CALL_LOCK	0x4

#define HYP_ABORT() hyp_abort(__func__, __FILE__, __LINE__)

void hyp_abort(const char *func, const char *file, int line);

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
 * @return zero on success or negative error code on failure
 */
int set_lockflags(uint64_t flags);

#endif
