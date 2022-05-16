// SPDX-License-Identifier: GPL-2.0-only

#ifndef CORE_CRYPTO_KEYSTORE_H_
#define CORE_CRYPTO_KEYSTORE_H_

typedef enum {NONE = 0, AES256, RSA2048} key_type_t;

int generate_key(kvm_guest_t *guest, uint8_t *key, size_t  *bufsize,
		 key_type_t key_type,
		 const char *name);
int get_key(const kvm_guest_t *guest, void *key, size_t *bufsize,
	    key_type_t type,
	    const char *name);
int delete_key(kvm_guest_t *guest, key_type_t type, const char *name);
int save_vm_key(const kvm_guest_t *guest, uint8_t *buf, size_t *buf_size);
int load_vm_key(kvm_guest_t *guest, const uint8_t *buf, size_t buf_size);
int set_guest_id(kvm_guest_t *guest, const uint8_t *id, size_t idlen);

#endif /* CORE_CRYPTO_KEYSTORE_H_ */
