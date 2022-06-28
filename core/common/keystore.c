// SPDX-License-Identifier: GPL-2.0-only

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "guest.h"
#include "heap.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/cipher.h"
#include "mbedtls/sha256.h"

#include "mbedtls/platform.h"
#include "keystore.h"
#include "mtree.h"

#define GUEST_KEK_GENERATION_SALT (const unsigned char *)"storesalt89w327"
#define KEY_NAME_LEN 16

#define KEY_STORAGE_MAGIC 0x11223344
#define KEY_STORAGE_VERSION 2
#define KEYSTORAGE_IV_LEN 16
#define HASH_LEN 32
#define MAX_KBUF_LEN 1024

#define CHECKRES(x, expected, err_handler) \
		do { \
			if ((x) != (expected)) { \
				goto err_handler; \
			} \
		} while (0)

typedef struct vm_key {
	key_type_t type;
	char name[KEY_NAME_LEN];
	uint8_t key[1];
} vm_key_t;

typedef struct keybuf {
	struct keybuf *next;
	uint32_t dbg;
	vm_key_t key;
} keybuf_t;

typedef struct {
	uint32_t magic;
	uint32_t version;
	uint8_t hash[HASH_LEN];
	uint8_t iv[KEYSTORAGE_IV_LEN];
} keys_header_t;

extern mbedtls_ctr_drbg_context ctr_drbg;

static int key_size(key_type_t type)
{
	switch (type) {
	case KEY_NONE: return 0;
	case AES256: return 32;
	case RSA2048: return 256;
	}
	return 0;
}

static keybuf_t *search_key_by_name(keybuf_t *p, key_type_t type, const char *name)
{
	while (p) {
		if (!strncmp(p->key.name, name, KEY_NAME_LEN) &&
		    p->key.type == type) {
			return p;
		}
		p = p->next;
	}
	return NULL;
}

static keybuf_t *new_key(uint8_t *key, key_type_t type, const char *name)
{
	keybuf_t *p;

	p = malloc(sizeof(keybuf_t) - 1 + key_size(type));
	if (p) {
		memset(p, 0, sizeof(keybuf_t));
		memcpy(p->key.key, key, key_size(type));
		memcpy(p->key.name, name, strnlen(name, 15) + 1);
		p->key.type = type;
	}
	return p;
}

static int add_key(keybuf_t *kbuf, uint8_t *key, key_type_t type,
		   const char *name)
{
	keybuf_t *p;

	p = search_key_by_name(kbuf, type, name);
	if (p) {
		memcpy(p->key.key, key, key_size(type));
		return 0;
	}
	if (kbuf) {
		p = kbuf;
		while (p->next) {
			p = p->next;
		}

		p->next = new_key(key, type, name);
		if (!p->next)
			return -ENOMEM;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int __delete_key(keybuf_t **kbuf, key_type_t type, const char *name)
{
	keybuf_t *prev = NULL;
	keybuf_t *p = *kbuf;

	while (p) {
		if (!strncmp(p->key.name, name, KEY_NAME_LEN) &&
		    p->key.type == type) {
			memset(p->key.key, 0, key_size(type));
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
		keysize = ROUND_UP(sizeof(vm_key_t) + key_size(p->key.type), 4);
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

int deserialize_vm_key(keybuf_t **keybuf, uint8_t *buf, size_t buf_size)
{
	uint32_t len = 0;
	uint32_t size;
	vm_key_t *p;

	while (len < buf_size) {
		p = (vm_key_t *)buf;
		if (*keybuf)
			add_key(*keybuf, p->key, p->type, p->name);
		else {
			*keybuf = new_key(p->key, p->type, p->name);
			if (!*keybuf) {
				return -ENOMEM;
			}
		}
		size = ROUND_UP(sizeof(vm_key_t) + key_size(p->type), 4);
		buf += size;
		len += size;
	}
	return 0;
}

static int encrypt_keys(uint8_t *key, uint8_t *iv, uint8_t *ctext,
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

static int decrypt_keys(uint8_t *key, uint8_t *iv,
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

int generate_key(kvm_guest_t *guest, uint8_t *key, size_t  *bufsize,
		 key_type_t type,
		 const char *name)
{
	uint8_t rand[32];
	int ret;
	int err = -EINVAL;

	if (*bufsize < key_size(type)) {
		goto err_handler;
	}
	if (type == AES256) {
		ret = mbedtls_ctr_drbg_random(&ctr_drbg, rand, 32);
		CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	}

	if (guest->keybuf) {
		ret = add_key(guest->keybuf, rand, type, name);
		CHECKRES(ret, 0, err_handler);
	} else {
		guest->keybuf = new_key(rand, type, name);
		if (!guest->keybuf) {
			err =  ENOMEM;
			goto err_handler;
		}
	}

	*bufsize = key_size(type);
	memcpy(key, rand, *bufsize);
	err = 0;

err_handler:
	memset(rand, 0, sizeof(rand));
	return err;
}

int get_key(const kvm_guest_t *guest, void *key, size_t *bufsize,
	    key_type_t type, const char *name)
{
	keybuf_t *p;

	p = search_key_by_name(guest->keybuf, type, name);
	if (p) {
		if (*bufsize < key_size(p->key.type)) {
			return -EINVAL;
		}
		memcpy(key, p->key.key, key_size(p->key.type));
		*bufsize =  key_size(p->key.type);
		return 0;
	}
	return -ENOKEY;
}

int delete_key(kvm_guest_t *guest, key_type_t type, const char *name)
{
	return __delete_key((keybuf_t **)&guest->keybuf, type, name);
}

int set_guest_id(kvm_guest_t *guest, const uint8_t *id, size_t idlen)
{
	if (idlen < MIN_UNIQUE_ID_LEN || idlen > MAX_UNIQUE_ID_LEN)
		return -EINVAL;

	memset(guest->unique_id, 0, MAX_UNIQUE_ID_LEN);
	memcpy(guest->unique_id, id, idlen);
	return 0;
}

int save_vm_key(const kvm_guest_t *guest, uint8_t *ctext, size_t *bufsize)
{
	uint8_t *ptext = NULL;
	size_t ptext_len = 0;
	size_t ctext_len;
	mbedtls_sha256_context ctx;
	uint8_t key[32];
	keys_header_t *keys_header;
	int ret = 0;
	int err = -EINVAL;

	keys_header = (keys_header_t *)ctext;
	if (!keys_header || *bufsize < sizeof(keys_header_t)) {
		goto err_handler;
	}
	keys_header->magic = KEY_STORAGE_MAGIC;
	keys_header->version = KEY_STORAGE_VERSION;
	memset(keys_header->iv, 0, 16);
	ret = mbedtls_ctr_drbg_random(&ctr_drbg,
				      keys_header->iv, KEYSTORAGE_IV_LEN - 2);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	serialize_vm_key(guest->keybuf, NULL, &ptext_len);
	if (ptext_len > MAX_KBUF_LEN) {
		ret =  -EINVAL;
		goto err_handler;
	}
	ptext = malloc(ptext_len);
	if (!ptext) {
		ret = -ENOMEM;
		goto err_handler;
	}

	ret = serialize_vm_key(guest->keybuf, ptext, &ptext_len);
	CHECKRES(ret, 0, err_handler);
	ret = mbedtls_sha256_ret(ptext, ptext_len, keys_header->hash, 0);
	CHECKRES(ret, 0, err_handler);
	ret = mbedtls_sha256_starts_ret(&ctx, 0);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_sha256_update_ret(&ctx,
					guest->unique_id,
					MAX_UNIQUE_ID_LEN);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	/* FIXME: Key generation is bad, please fix it
	 */
	ret =  mbedtls_sha256_update_ret(&ctx,
					 GUEST_KEK_GENERATION_SALT,
					 sizeof(GUEST_KEK_GENERATION_SALT));
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	ret = mbedtls_sha256_finish_ret(&ctx, key);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ctext_len = *bufsize - sizeof(keys_header_t);
	ret = encrypt_keys(key, keys_header->iv, ctext + sizeof(keys_header_t),
			   &ctext_len, ptext, ptext_len);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	*bufsize = ctext_len + sizeof(keys_header_t);

	err = 0;

err_handler:
	if (ptext)
		free(ptext);
	memset(key, 0, sizeof(key));
	mbedtls_sha256_free(&ctx);
	return err;
}

int load_vm_key(kvm_guest_t *guest, const uint8_t *ctext, size_t ctext_len)
{
	uint8_t *ptext = NULL;
	size_t ptext_len;
	mbedtls_sha256_context ctx;
	keys_header_t *key_hdr;
	uint8_t key[32];
	uint8_t hash[HASH_LEN];
	int ret;
	int err = -EINVAL;

	key_hdr = (keys_header_t *)ctext;
	if (!key_hdr || ctext_len < sizeof(keys_header_t)) {
		goto err_handler;
	}
	if (key_hdr->magic != KEY_STORAGE_MAGIC ||
	    key_hdr->version != KEY_STORAGE_VERSION) {
		goto err_handler;
	}
	ret = mbedtls_sha256_starts_ret(&ctx, 0);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ret = mbedtls_sha256_update_ret(&ctx,
					guest->unique_id,
					MAX_UNIQUE_ID_LEN);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	/* FIXME: Key generation is bad, please fix it
	 */
	ret = mbedtls_sha256_update_ret(&ctx,
					GUEST_KEK_GENERATION_SALT,
					sizeof(GUEST_KEK_GENERATION_SALT));
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);

	ret = mbedtls_sha256_finish_ret(&ctx, key);
	CHECKRES(ret, MBEDTLS_EXIT_SUCCESS, err_handler);
	ctext_len -= sizeof(keys_header_t);
	ret = decrypt_keys(key, key_hdr->iv, &ptext, &ptext_len,
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
	memset(key, 0, sizeof(key));
	mbedtls_sha256_free(&ctx);
	return err;
}
