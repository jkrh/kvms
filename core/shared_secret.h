// SPDX-License-Identifier: GPL-2.0-only

#ifndef SHARED_SECRET_H_
#define SHARED_SECRET_H_
/***
 * Derive a key from shared secret
 * @param guest the guest
 * @param key  the pointer to the derived key
 * @param key_size the size of the key
 * @param salt the salt for key derivation
 * @return zero in case of success
 */

int  get_derived_key(kvm_guest_t *guest, void *key, size_t key_size,
		     const void *salt, size_t salt_size);
#endif /* SHARED_SECRET_H_ */