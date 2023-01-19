// SPDX-License-Identifier: GPL-2.0-only

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "guest.h"
#include "heap.h"
#include "hyplogs.h"
#include "armtrans.h"
#include "platform_api.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/aes.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"

#include "keystore.h"
#include "mtree.h"


#define CHECKRES(x, expected, err_handler) \
		do { \
			if ((x) != (expected)) { \
				goto err_handler; \
			} \
		} while (0)

typedef struct {
	uint32_t magic;
	uint32_t version;
	uint8_t hash[HASH_LEN];
	uint8_t iv[KEYSTORAGE_IV_LEN];
} keys_header_t;

extern mbedtls_ctr_drbg_context ctr_drbg;

static bool is_valid_paddr(const void *addr)
{
	if (!addr || addr == (void *) ~0)
		return false;
	else
		return true;

}

static keybuf_t *search_key_by_name(keybuf_t *p, const char *name)
{
	while (p) {
		if (!strncmp(p->key.name, name, KEY_NAME_LEN)) {
			return p;
		}
		p = p->next;
	}
	return NULL;
}

static keybuf_t *new_key(const uint8_t *key, size_t key_size,
			 key_type_t type, const char *name)
{
	keybuf_t *p = malloc(sizeof(keybuf_t) - 1 + key_size);

	if (p) {
		memset(p, 0, sizeof(keybuf_t));
		memcpy(p->key.key, key, key_size);
		memcpy(p->key.name, name, strnlen(name, 15) + 1);
		p->key.type = type;
		p->key.size = key_size;
	}

	return p;
}

static int add_key(keybuf_t *kbuf, const uint8_t *key, size_t key_size,
		   key_type_t type, const char *name)
{
	keybuf_t *p = search_key_by_name(kbuf, name);

	if (p) {
		memcpy(p->key.key, key, key_size);
		p->key.size = key_size;
		p->key.type = type;
		return 0;
	}

	if (kbuf) {
		p = kbuf;
		while (p->next) {
			p = p->next;
		}

		p->next = new_key(key, key_size, type, name);
		if (!p->next)
			return -ENOMEM;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int __delete_key(keybuf_t **kbuf, const char *name)
{
	keybuf_t *prev = NULL;
	keybuf_t *p = *kbuf;

	while (p) {
		if (!strncmp(p->key.name, name, KEY_NAME_LEN) &&
		    p->key.type == GENERATED) {
			memset(p->key.key, 0, p->key.size);
			p->key.type = KEY_NONE;
			if (prev) {
				prev->next = p->next;
			} else {
				*kbuf = p->next;
			}
			free(p);
			return 0;
		}
		prev = p;
		p = p->next;
	}
	return -ENOKEY;
}

static int serialize_vm_key(const keybuf_t *p, uint8_t *buf, size_t *buf_size)
{
	uint32_t len = 0;
	uint32_t copyfail = 0;
	uint32_t keysize;

	while (p) {
		keysize = ROUND_UP(sizeof(vm_key_t) + p->key.size, 4);
		if ((*buf_size >= (len + keysize)) && buf && !copyfail) {
			memcpy(buf, &p->key, keysize);
			buf += keysize;
			len +=  keysize;
		} else {
			copyfail = 1;
			len += keysize;
		}
		p = p->next;
	}
	*buf_size = len;
	return copyfail;
}

static int deserialize_vm_key(keybuf_t **keybuf,
			      const uint8_t *buf, size_t buf_size)
{
	uint32_t len = 0;
	uint32_t size;
	vm_key_t *key;

	while (len < buf_size) {
		key = (vm_key_t *)buf;
		if (*keybuf)
			add_key(*keybuf, key->key, key->size,
				key->type, key->name);
		else {
			*keybuf = new_key(key->key, key->size,
					  key->type, key->name);
			if (!*keybuf) {
				return -ENOMEM;
			}
		}
		size = ROUND_UP(sizeof(vm_key_t) + key->size, 4);
		buf += size;
		len += size;
	}
	return 0;
}

static int encrypt_keys(const uint8_t *key, const uint8_t *iv, uint8_t *ctext,
			size_t *clen,
			const uint8_t *ptext, size_t plen)
{
	mbedtls_aes_context ctx;
	uint8_t stream_block[16];
	uint8_t tmp[KEYSTORAGE_IV_LEN];
	size_t ns = 0;
	int ret;
	int err = -EINVAL;

	if (*clen < plen) {
		goto err_handler;
	}
	*clen = plen;
	memcpy(tmp, iv, KEYSTORAGE_IV_LEN);
	mbedtls_aes_init(&ctx);
	ret = mbedtls_aes_setkey_enc(&ctx, key, 256);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	ret = mbedtls_aes_crypt_ctr(&ctx, plen, &ns, tmp, stream_block,
				    ptext, ctext);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	err = 0;

err_handler:
	mbedtls_aes_free(&ctx);
	memset(stream_block, 0, sizeof(stream_block));
	return err;
}

static int decrypt_keys(const uint8_t *key, const uint8_t *iv,
			uint8_t **ptext, size_t *plen,
			const uint8_t *ctext, size_t clen)
{
	mbedtls_aes_context ctx;
	uint8_t stream_block[16];
	uint8_t tmp[KEYSTORAGE_IV_LEN];
	size_t ns = 0;
	int ret;
	int err = -EINVAL;

	memcpy(tmp, iv, KEYSTORAGE_IV_LEN);
	mbedtls_aes_init(&ctx);
	ret = mbedtls_aes_setkey_enc(&ctx, key, 256);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	*ptext = malloc(clen);
	if (!*ptext) {
		err = -ENOMEM;
		goto err_handler;
	}
	*plen = clen;
	ret = mbedtls_aes_crypt_ctr(&ctx, clen, &ns, tmp, stream_block,
				    ctext, *ptext);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	err = 0;

err_handler:
	mbedtls_aes_free(&ctx);
	memset(stream_block, 0, sizeof(stream_block));
	return err;
}

static int __generate_key(keybuf_t **kbuf, uint8_t *key, size_t key_size,
		 const char *name)
{
	int ret;
	int err = -EINVAL;

	ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, key_size);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	if (*kbuf) {
		ret = add_key(*kbuf, key, key_size, GENERATED, name);
		CHECKRES(ret, 0, err_handler);
	} else {
		*kbuf = new_key(key, key_size, GENERATED, name);
		if (!*kbuf) {
			err =  ENOMEM;
			goto err_handler;
		}
	}
	err = 0;

err_handler:
	return err;
}

int generate_key(kvm_guest_t *guest, uint8_t *a_key, size_t size,
		const char *a_name)
{
	char name[KEY_NAME_LEN];
	uint8_t *key = NULL;
	int ret = -EINVAL;

	if (!kernel_integrity_ok(guest) ||
	     size > MAX_KEY_SIZE)
		goto err_handler;

	if (copy_from_guest(guest, STAGEA, name, a_name, KEY_NAME_LEN) < 0)
		goto err_handler;

	key = malloc(size);
	if (!key)
		goto err_handler;

	if (__generate_key((keybuf_t **)&guest->keybuf, key, size, name))
		goto err_handler;

	if (copy_to_guest(guest, STAGEA, a_key, key, size) < 0)
		goto err_handler;

	ret = 0;

err_handler:
	if (key) {
		memset(key, 0, size);
		free(key);
	}
	return ret;
}

int import_key(kvm_guest_t *guest, uint8_t *key, size_t size,
		 const char *name)
{
	int ret;
	int err = -EINVAL;

	if (!kernel_integrity_ok(guest) ||
	     size > MAX_KEY_SIZE)
		goto err_handler;

	if (guest->keybuf) {
		ret = add_key(guest->keybuf, key, size, IMPORTED, name);
		CHECKRES(ret, 0, err_handler);
	} else {
		guest->keybuf = new_key(key, size, IMPORTED, name);
		if (!guest->keybuf) {
			err =  ENOMEM;
			goto err_handler;
		}
	}

	err = 0;

err_handler:
	return err;
}

static int __get_key(keybuf_t *kbuf, void *key, size_t *size,
	   const char *name)
{
	keybuf_t *p;


	p = search_key_by_name(kbuf, name);
	if (p) {
		if (*size < p->key.size) {
			return -EINVAL;
		}
		memcpy(key, p->key.key, p->key.size);
		*size = p->key.size;
		return 0;
	}
	return -ENOKEY;
}

int get_key(kvm_guest_t *guest, void *a_key, size_t *a_size,
	   const char *a_name)
{
	char name[KEY_NAME_LEN];
	uint8_t *key = NULL;
	size_t size;
	int ret;
	int err = -EINVAL;

	if (!kernel_integrity_ok(guest))
		goto err_handler;
	if (copy_from_guest(guest, STAGEA, &size, a_size, sizeof(size_t)) < 0)
		goto err_handler;

	if (size > MAX_KEY_SIZE)
		goto err_handler;

	if (copy_from_guest(guest, STAGEA, name, a_name, KEY_NAME_LEN) < 0)
		goto err_handler;

	key = malloc(size);
	if (!key) {
		err = -ENOMEM;
		goto err_handler;
	}

	ret = __get_key(guest->keybuf, key, &size, name);
	if (ret) {
		err = ret;
		goto err_handler;
	}

	if (copy_to_guest(guest, STAGEA, a_size, &size, sizeof(size_t)) < 0)
		goto err_handler;
	if (copy_to_guest(guest, STAGEA, a_key, key, size) < 0)
		goto err_handler;

	err = 0;

err_handler:
	if (key) {
		memset(key, 0, size);
		free(key);
	}
	return err;

}

int delete_key(kvm_guest_t *guest, const char *name)
{
	if (!is_valid_paddr(name) ||
	    !kernel_integrity_ok(guest))
		return -EINVAL;
	return __delete_key((keybuf_t **)&guest->keybuf, name);
}

/* Set guest id*/
int set_guest_id(kvm_guest_t *guest, const uint8_t *id, size_t idlen)
{
	if (!is_valid_paddr(id) ||
	    !kernel_integrity_ok(guest))
		return -EINVAL;

	if (idlen > GUEST_ID_LEN)
		idlen = GUEST_ID_LEN;
	memcpy(guest->guest_id, id, idlen);

	return 0;
}

int save_vm_key(const kvm_guest_t *guest, uint8_t *ctext, size_t *bufsize)
{
	uint8_t *ptext = NULL;
	size_t ptext_len = 0;
	size_t ctext_maxlen;
	uint8_t kek[32];
	keys_header_t *keys_header;
	uint8_t salt[GUEST_ID_LEN + KEYSTORE_SALT_SIZE];
	int ret = 0;
	int err = -EINVAL;
	keys_header = (keys_header_t *)ctext;

	if (!is_valid_paddr(ctext) ||
	    !is_valid_paddr(bufsize) ||
	    !guest ||
	    !kernel_integrity_ok(guest) ||
	    !ctext ||
	    *bufsize < sizeof(keys_header_t))
		return -EINVAL;

	/* generate header */
	keys_header->magic = KEY_STORAGE_MAGIC;
	keys_header->version = KEY_STORAGE_VERSION;
	memset(keys_header->iv, 0, 16);
	ret = mbedtls_ctr_drbg_random(&ctr_drbg,
				      keys_header->iv, KEYSTORAGE_IV_LEN - 2);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	/* calculate buffer size */
	serialize_vm_key(guest->keybuf, NULL, &ptext_len);

	ptext = malloc(ptext_len);
	if (!ptext) {
		ret = -ENOMEM;
		goto err_handler;
	}

	ret = serialize_vm_key(guest->keybuf, ptext, &ptext_len);
	CHECKRES(ret, 0, err_handler);
	ret = mbedtls_sha256_ret(ptext, ptext_len, keys_header->hash, 0);
	CHECKRES(ret, 0, err_handler);

	/*generate KEK for guest*/
	memcpy(salt, guest->guest_id, GUEST_ID_LEN);
	memcpy(&salt[GUEST_ID_LEN], KEYSTORE_SALT,  KEYSTORE_SALT_SIZE);
	ret = platform_get_static_key(kek, sizeof(kek), salt, sizeof(salt));
	CHECKRES(ret, 0, err_handler);

	ctext_maxlen = *bufsize - sizeof(keys_header_t);
	ret = encrypt_keys(kek, keys_header->iv, ctext + sizeof(keys_header_t),
			   &ctext_maxlen, ptext, ptext_len);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	*bufsize = ctext_maxlen + sizeof(keys_header_t);
	if (*bufsize  > MAX_KEY_STORAGE_SIZE) {
		ERROR("WARNING: Very large key storage: %d býtes\n", *bufsize);
		ERROR("WARNING: It is not possible to read it back\n");
	}

	err = 0;

err_handler:
	if (ptext)
		free(ptext);
	memset(kek, 0, sizeof(kek));
	return err;
}

int load_vm_key(kvm_guest_t *guest, const uint8_t *ctext, size_t ctext_len)
{
	uint8_t *ptext = NULL;
	size_t ptext_len;
	keys_header_t *key_hdr = (keys_header_t *)ctext ;
	uint8_t kek[32];
	uint8_t hash[HASH_LEN];
	uint8_t salt[GUEST_ID_LEN + KEYSTORE_SALT_SIZE];
	int ret;
	int err = -EINVAL;

	if (!is_valid_paddr(ctext) ||
	    !guest ||
	    !kernel_integrity_ok(guest) ||
	    !ctext ||
	    ctext_len > MAX_KEY_STORAGE_SIZE ||
	    ctext_len < sizeof(keys_header_t))
		return -EINVAL;

	if (key_hdr->magic != KEY_STORAGE_MAGIC ||
	    key_hdr->version != KEY_STORAGE_VERSION) {
		goto err_handler;
	}

	/*generate KEK for guest*/
	memcpy(salt, guest->guest_id, GUEST_ID_LEN);
	memcpy(&salt[GUEST_ID_LEN], KEYSTORE_SALT,  KEYSTORE_SALT_SIZE);
	ret = platform_get_static_key(kek, sizeof(kek), salt, sizeof(salt));
	CHECKRES(ret, 0, err_handler);

	ctext_len -= sizeof(keys_header_t);
	ret = decrypt_keys(kek, key_hdr->iv, &ptext, &ptext_len,
			   ctext + sizeof(keys_header_t), ctext_len);
	CHECKRES(ret, 0, err_handler);

	ret = mbedtls_sha256_ret(ptext, ptext_len, hash, 0);
	CHECKRES(ret, 0, err_handler);
	if (memcmp(hash, key_hdr->hash, HASH_LEN)) {
		goto err_handler;
	}

	ret = deserialize_vm_key((keybuf_t **) &guest->keybuf,
			    ptext, ptext_len);
	CHECKRES(ret, 0, err_handler);
	err = 0;

err_handler:
	if (ptext)
		free(ptext);
	memset(kek, 0, sizeof(kek));
	return err;
}
