/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __HVCCALL_H__
#define __HVCCALL_H__

#include "hvccall-defines.h"

#define HYP_ABORT() hyp_abort(__func__, __FILE__, __LINE__)

void hyp_abort(const char *func, const char *file, int line);
void dump_state(uint64_t level, void *sp);

#endif
