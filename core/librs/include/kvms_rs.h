// SPDX-License-Identifier: GPL-2.0-only

#ifndef __KVMS_RS_H__
#define __KVMS_RS_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

int32_t gettimeofday(struct timeval *tv);
int32_t usleep(uint64_t usec);

typedef union spinlock {
	uint32_t	__val;
	struct {
		uint16_t owner, next;
	};
} spinlock_t;
#define __SPIN_LOCK_INITIALIZER \
	{ .__val = 0 }
#define __SPIN_LOCK_UNLOCKED \
	((spinlock_t) __SPIN_LOCK_INITIALIZER)
#define DEFINE_SPINLOCK(x)  spinlock_t x = __SPIN_LOCK_UNLOCKED
#define spin_lock_init(l)			\
do {						\
	*(l) = __SPIN_LOCK_UNLOCKED;		\
} while (0)
void spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);

#endif /* __KVMS_RS_H__ */
