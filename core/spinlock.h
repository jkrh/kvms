/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

extern void spin_lock(void *lock);
extern void spin_unlock(void *lock);

#endif // __SPINLOCK_H__
