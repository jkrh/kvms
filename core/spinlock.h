/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <stdint.h>

#include "helpers.h"

typedef uint64_t spinlock_t ALIGN(8);

extern void spin_lock(spinlock_t *lock);
extern void spin_unlock(spinlock_t *lock);

#endif // __SPINLOCK_H__
