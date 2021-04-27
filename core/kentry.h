/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KENTRY_H__
#define __KENTRY_H__

#include "guest.h"

void __enter_el1_cold(kernel_func_t *, void *);
void __enter_el1_warm(kernel_func_t *, void *);

#endif
