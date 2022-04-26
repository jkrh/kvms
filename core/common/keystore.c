// SPDX-License-Identifier: GPL-2.0-only

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "guest.h"
#include "heap.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "keystore.h"

#define KEY_NAME_LEN 16

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

extern mbedtls_ctr_drbg_context ctr_drbg;
extern kvm_guest_t guest[4];

static int key_size(key_type_t type)
{
	switch (type) {
	case NONE: return 0;
	case AES256: return 32;
	case RSA2048: return 256;
	}

	return 0;
}

static keybuf_t *search_key_by_name(keybuf_t *p, key_type_t type, char *name)
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

static keybuf_t *new_key(uint8_t *key, key_type_t type, char *name)
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

static int add_key(keybuf_t **kbuf, uint8_t *key, key_type_t type, char *name)
{
	keybuf_t *p;

	p = search_key_by_name(*kbuf, type, name);
	if (p) {
		memcpy(p->key.key, key, key_size(type));
		return 0;
	}
	if (*kbuf) {
		p = *kbuf;
		while (p->next) {
			p = p->next;
		}

		p->next = new_key(key, type, name);
		if (!p->next)
			return -ENOMEM;
	} else {
		*kbuf = new_key(key, type, name);
		if (!*kbuf) {
			return -ENOMEM;
		}
	}

	return 0;
}

static int __delete_key(keybuf_t **kbuf, key_type_t type, char *name)
{
	keybuf_t *prev = NULL;
	keybuf_t *p = *kbuf;

	while (p) {
		if (!strncmp(p->key.name, name, KEY_NAME_LEN) &&
		    p->key.type == type) {
			memset(p->key.key, 0, key_size(type));
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

static int __save_vm_key(keybuf_t *p, uint8_t *buf, uint32_t *buf_size)
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

int __load_vm_key(keybuf_t **keybuf, uint8_t *buf, uint32_t buf_size)
{
	uint32_t len = 0;
	uint32_t size;
	vm_key_t *p;

	while (len < buf_size) {
		p = (vm_key_t *)buf;
		add_key(keybuf, p->key, p->type, p->name);
		size = ROUND_UP(sizeof(vm_key_t) + key_size(p->type), 4);
		buf += size;
		len += size;
	}
	return 0;
}

static int encrypt_keys(kvm_guest_t *guest, uint8_t *ctext, uint32_t *ctext_len,
			uint8_t *ptext, uint32_t ptext_len)
{
	/* if cipher is memcpy() then cipher text length is same as plain
	 * text length
	 */
	if (*ctext_len < ptext_len) {
		return -EINVAL;
	}
	*ctext_len = ptext_len;

	/* TODO: Use better encryption method */
	memcpy(ctext, ptext, ptext_len);
	return 0;
}

static int decrypt_keys(kvm_guest_t *guest, uint8_t **ptext, uint32_t *ptext_len,
			uint8_t *ctext, uint32_t ctext_len)
{
	/* if cipher is memcpy() then cipher text length is same as plain
	 * text length
	 */
	*ptext = malloc(ctext_len);
	if (!*ptext) {
		return -ENOMEM;
	}
	/* TODO: Use better encryption method */
	*ptext_len = ctext_len;
	memcpy(*ptext, ctext, ctext_len);
	return 0;
}

int generate_key(kvm_guest_t *guest, uint8_t *key, uint32_t  *bufsize,
		 key_type_t key_type,
		 char *name)
{
	uint8_t rand[32];
	int rv;

	if (*bufsize < key_size(key_type)) {
		return -1;
	}
	if (key_type == AES256) {
		rv = mbedtls_ctr_drbg_random(&ctr_drbg, rand, 32);
		if (rv != MBEDTLS_EXIT_SUCCESS) {
			return -EFAULT;
		}
	}
	rv = add_key((keybuf_t **)&guest->keybuf, rand, key_type, name);
	if (rv) {
		return rv;
	}
	*bufsize = key_size(key_type);
	memcpy(key, rand, *bufsize);
	return 0;
}

int get_key(kvm_guest_t *guest, void *key, uint32_t *bufsize, key_type_t type, char *name)
{
	keybuf_t *p;

	p = search_key_by_name(guest->keybuf, type, name);
	if (p) {
		if (*bufsize < key_size(p->key.type)) {
			return -1;
		}
		memcpy(key, p->key.key, key_size(p->key.type));
		*bufsize =  key_size(p->key.type);
		return 0;
	}
	return -ENOKEY;
}

int delete_key(kvm_guest_t *guest, key_type_t type, char *name)
{
	return __delete_key((keybuf_t **)&guest->keybuf, type, name);
}

int save_vm_key(kvm_guest_t *guest, uint8_t *ctext, uint32_t *bufsize)
{
	uint8_t *ptext;
	uint32_t ptext_len = 0;
	int res;

	__save_vm_key(guest->keybuf, NULL, &ptext_len);
	ptext = malloc(ptext_len);
	if (!ptext) {
		printf("malloc error\n");
		res = -ENOMEM;
		return res;
		}
	res = __save_vm_key(guest->keybuf, ptext, &ptext_len);
	if (!res) {
		res = encrypt_keys(guest, ctext, bufsize, ptext, ptext_len);
	}
	free(ptext);
	return res;
}

int load_vm_key(kvm_guest_t *guest, uint8_t *ctext, uint32_t size)
{
	uint8_t *ptext;
	uint32_t ptext_len;
	int res;

	res = decrypt_keys(guest, &ptext, &ptext_len, ctext, size);
	if (!res) {
		res = __load_vm_key((keybuf_t **)&guest->keybuf, ptext, ptext_len);
	}
	free(ptext);
	return res;
}
