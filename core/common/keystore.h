// SPDX-License-Identifier: GPL-2.0-only

#ifndef CORE_COMMON_KEYSTORE_H_
#define CORE_COMMON_KEYSTORE_H_

#define KEY_NAME_LEN 16
#define MAX_KEY_SIZE 256
#define MAX_KEY_STORAGE_SIZE 4096

#define KEY_STORAGE_MAGIC 0x11223344
#define KEY_STORAGE_VERSION 2

#define KEYSTORE_SALT ((const unsigned char *)"storagesalt")
#define KEYSTORE_SALT_SIZE (sizeof(KEYSTORE_SALT))

#define KEYSTORAGE_IV_LEN 16
#define HASH_LEN 32

typedef enum {KEY_NONE = 0, GENERATED, IMPORTED} key_type_t;

typedef struct {
	key_type_t type;
	size_t size;
	char name[KEY_NAME_LEN];
	uint8_t key[0];
} vm_key_t;

typedef struct keybuf {
	struct keybuf *next;
	vm_key_t key;
} keybuf_t;

/* Set guest specific ID. Used by hypervisor
*
* @param guest, the guest
* @param id, ID
* @param id_len, a size of ID
* @return zero on success or negative error code on failure
*/
int set_guest_id(kvm_guest_t *guest, const uint8_t *id, size_t idlen);

/**
 * Import a key. Used for importing a key from hypervisor
 *
 * @param guest, the guest
 * @param key, the key
 * @param key_size, a size of yhe key
 * @param name, a name of the key
 * @return zero on success or negative error code on failure
 */
int import_key(kvm_guest_t *guest, uint8_t *key, size_t key_size,
		 const char *name);

/**
 * Generate a key, Used for generating a key by guest HVC call
 *
 * @param guest, the guest
 * @param key, a pointer where the key will be stored
 * @param key_size, a size of the key
 * @param name, a name of the key
 * @return zero on success or negative error code on failure
 */
int generate_key(kvm_guest_t *guest, uint8_t *key, size_t key_size,
		 const char *name);

/**
 * Read the previously generated key, Used by guest HVC call
 *
 * @param guest, the guest
 * @param key, a pointer where the key will be stored
 * @param key_size, a size of the key
 * @param name, a name of the key
 * @return zero on success or negative error code on failure
 */
int get_key(kvm_guest_t *guest, void *key, size_t *bufsize,
	    const char *name);

/**
 * Delete the previously generated key. Used by guest HVC call
 *
 * @param guest, the guest
 * @param name, a name of the key
 * @return zero on success or negative error code on failure
 */
int delete_key(kvm_guest_t *guest, const char *name);

/**
 * Save and encrypt guest guest keys Used by jost HVC call
 *
 * @param guest, the guest
 * @param n´buf, a pointer where the keys will be stored
 * @param buf_size, a size of buf
 * @return zero on success or negative error code on failure
 */
int save_vm_key(const kvm_guest_t *guest, uint8_t *buf, size_t *buf_size);
/**
 * Load and gecrypt guest guest keys Used by host HVC call
 *
 * @param guest, the guest
 * @param n´buf, a pointer where the keys will be red
 * @param buf_size, a size of buf
 * @return zero on success or negative error code on failure
 */
int load_vm_key(kvm_guest_t *guest, const uint8_t *buf, size_t buf_size);

#endif /* CORE_COMMON_KEYSTORE_H_ */
