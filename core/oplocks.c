// SPDX-License-Identifier: GPL-2.0-only

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "hyplogs.h"
#include "oplocks.h"
#include "armtrans.h"

static uint64_t hostflags;

int set_lockflags(uint64_t flags, uint64_t addr, size_t sz, uint64_t depth)
{
	LOG("flags: 0x%lx addr: 0x%lx sz: 0x%lx depth: 0x%lx\n",
	     flags, addr, sz, depth);
#if (DEBUG == 2)
	return 0;
#endif
	hostflags |= flags & HOST_LOCKFLAG_MASK;
	if (flags & HOST_PT_LOCK)
		return lock_host_kernel_area(addr, sz, depth);

	return 0;
}

int is_locked(uint64_t lock)
{
	return hostflags & (lock & HOST_LOCKFLAG_MASK);
}
