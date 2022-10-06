/* SPDX-License-Identifier: GPL-2.0-only */

#include <string.h>
#include <hyplogs.h>
#include "spinlock.h"

void spin_rwlock_init(rwlock_t *lock)
{
	memset(lock, 0, sizeof(*lock));
}

void spin_read_lock(rwlock_t *lock)
{
	spin_lock(&lock->__r);
	if (lock->__b == 254)
		panic("too many lock readers\n");
	lock->__b++;
	if (lock->__b == 1)
		spin_lock(&lock->__w);
	spin_unlock(&lock->__r);
}

void spin_read_unlock(rwlock_t *lock)
{
	spin_lock(&lock->__r);
	if (lock->__b == 0) {
		ERROR("lock 0x%lx not set\n", lock);
		goto out_unlock;
	}
	lock->__b--;
	if (lock->__b == 0)
		spin_unlock(&lock->__w);
out_unlock:
	spin_unlock(&lock->__r);
}

void spin_write_lock(rwlock_t *lock)
{
	spin_lock(&lock->__w);
}

void spin_write_unlock(rwlock_t *lock)
{
	spin_unlock(&lock->__w);
}

