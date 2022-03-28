// SPDX-License-Identifier: GPL-2.0-only

#ifndef __OPLOCKS_H__
#define __OPLOCKS_H__

#include "hvccall-defines.h"

/**
 * Setup hypervisor operational locks. See hvccall-defines.h for all the
 * possible locks to set.
 *
 * @param flags, the lock flags
 * @param addr, sz, and depth are conditionals for el1 page table locking.
 *        See the page table lock api description in armtrans.h.
 * @return zero on success or error code on failure
 */
int set_lockflags(uint64_t flags, uint64_t addr, size_t sz, uint64_t depth);

/**
 * Check if any give the lock locks are set.
 *
 * @param lock, the lock bitmask. See hvccall-defines.h.
 * @return false if not, true otherwise.
 */
int is_locked(uint64_t lock);

#endif
