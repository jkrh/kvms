// SPDX-License-Identifier: GPL-2.0-only

#ifndef CORE_CRYPTO_KEYSTORE_H_
#define CORE_CRYPTO_KEYSTORE_H_

typedef enum {KEY_NONE = 0, AES256, RSA2048} key_type_t;

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
int set_guest_own_id(kvm_guest_t *guest, const uint8_t *id, size_t idlen);
#ifdef DEBUG
static inline int generate_host_key(uint8_t *key, size_t  *bufsize,
		 key_type_t type,
		 const char *name)
{
	kvm_guest_t *guest =  get_guest(HOST_VMID);

	return generate_key(guest, key, bufsize, type, name);
}
#else
static inline int generate_host_key(uint8_t *key, size_t  *bufsize,
		      key_type_t type,
		      const char *name)
{
	return 0;
}
#endif
#ifdef DEBUG
static inline int get_host_key(uint8_t *key, size_t  *bufsize,
		 key_type_t type,
		 const char *name)
{
	kvm_guest_t *guest =  get_guest(HOST_VMID);

	return get_key(guest, key, bufsize, type, name);
}
#else
static inline int get_host_key(uint8_t *key, size_t  *bufsize,
		      key_type_t type,
		      const char *name)
{
	return 0;
}
#endif
#endif /* CORE_CRYPTO_KEYSTORE_H_ */
