/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <stdint.h>

#include "commondefines.h"

typedef uint64_t spinlock_t ALIGN(8);
typedef struct {
	spinlock_t __r;
	spinlock_t __w;
	uint8_t __b;
} rwlock_t ALIGN(8);


/*
 * spin_lock - acquire a lock on critical section
 *
 * Note: the lock is not recursive. Acquire it twice and you will
 * deadlock.
 */
void spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);

/*
 * Very simple reader-writer lock
 *
 * Multiple readers ok, single writer. Lock supports recursion for read,
 * write doesn't.
 */
void spin_rwlock_init(rwlock_t *lock);
void spin_read_lock(rwlock_t *lock);
void spin_read_unlock(rwlock_t *lock);

void spin_write_lock(rwlock_t *lock);
void spin_write_unlock(rwlock_t *lock);

#endif // __SPINLOCK_H__
