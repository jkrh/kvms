// SPDX-License-Identifier: GPL-2.0-only

#include <stdio.h>
#include <stdlib.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "guest.h"
#include "keystore.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/sha256.h"


typedef struct kvm_guest kvm_guest_t;
typedef uint8_t keys_t[MAX_KEY_SIZE];

void hexdump(uint8_t *p, uint32_t len);
int mbed_entropy(void *data, unsigned char *entropy, size_t len,
		 size_t *olen);

kvm_guest_t guest[4];
uint8_t crypto_buf[1024];
static uint8_t heap[1024];

struct mbedtls_entropy_context mbedtls_entropy_ctx;
struct mbedtls_ctr_drbg_context ctr_drbg;

#define OK 0
#define TEST_GEN_KEY(name, key, size, exp) { \
		int ret = generate_key(&guest[0], keys[key], size, "key-"#key); \
		checkret(#name, ret, exp); \
	}

#define TEST_GET_KEY(name, key, size, bsize, exp) { \
		size_t bs = bsize;\
		int ret = get_key(&guest[0], buf, &bs, "key-"#key); \
		if (!checkret(#name, ret, exp)); \
			if (!ret && (checkkey(keys[key], size, buf, bs))) \
				pr_error("keys0", keys[key], buf); \
	}

#define TEST_DEL_KEY(name, key, exp) { \
		checkret(#name, delete_key(&guest[0], "key-"#key), exp); \
	}

void pr_error(char *txt, uint8_t *b1, uint8_t *b2)
{
	printf("Error %s\n", txt);
	hexdump(b1, 32);
	hexdump(b2, 32);
}
int checkret(char *txt, int ret, int exp)
{
	if (ret == exp) {
		printf("%s OK\n", txt);
		return 0;
	} else {
		printf("%s FAIL, expected %d, actual : %d\n", txt, exp, ret);
		return 1;
	}
}

int checkkey(uint8_t *a, size_t alen, uint8_t *b, size_t blen)
{
	int ret;

	if (alen != blen) {
		return 2;
	}

	ret = memcmp(a, b, alen);

	if (ret == 0) {
		memset(b, 0, alen);
	}
	return ret;
}

int main(void)
{
	uint8_t savebuf[MAX_KEY_STORAGE_SIZE];
	size_t savebuf_size = sizeof(savebuf);
	keys_t keys[8];
	size_t bufsize;
	size_t keysize;
	uint8_t buf[MAX_KEY_SIZE];

	int ret;

	printf("Start\n");
	memset(heap, 0, sizeof(heap));
	mbedtls_memory_buffer_alloc_init(crypto_buf, sizeof(crypto_buf));

	mbedtls_entropy_init(&mbedtls_entropy_ctx);
	mbedtls_entropy_add_source(&mbedtls_entropy_ctx, mbed_entropy, NULL, 8,
				   MBEDTLS_ENTROPY_SOURCE_STRONG);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
			      &mbedtls_entropy_ctx, 0, 0);
	guest[0].keybuf = NULL;

	TEST_GEN_KEY(Genkey 32B key, 1, 32, OK);
	TEST_GET_KEY(Getkey 32B key, 1, 32, 32, OK);
	TEST_GEN_KEY(Gen 48B key, 2, 48, OK);
	TEST_GET_KEY(Get 48B key, 2, 48, 48, OK);
	TEST_GET_KEY(Get 48B key small buffer, 2, 48, 46, -EINVAL);
	TEST_GET_KEY(Get 48B key larger buffer, 2, 48, 50, OK);
	TEST_GET_KEY(Get unexisting key, 3, 48, 48, -ENOKEY);
	TEST_DEL_KEY(Delete a key, 2, OK);
	TEST_GET_KEY(Is the key deleted, 2, 48, 48, -ENOKEY);
	TEST_DEL_KEY(Delete the latest key, 1, OK);
	TEST_GET_KEY(Is the key deleted, 1, 48, 48, -ENOKEY);
	TEST_GEN_KEY(Genkey 32B key, 1, 32, OK);
	TEST_GEN_KEY(Genkey 32B key, 2, 32, OK);
	TEST_GEN_KEY(Genkey 48B key, 3, 48, OK);
	TEST_GEN_KEY(Genkey 64B key, 4, 64, OK);
	TEST_GET_KEY(Get 64B key, 4, 64, 64, OK);
	ret = save_vm_key(&guest[0], savebuf, &savebuf_size);
	if (ret == OK)
		printf("save_vm_keys OK\n");
	else
		printf("save_vm_keys ret: %x, bufsize %ld FAIL\n",
			ret, savebuf_size);

	TEST_GET_KEY(Get 48B key, 3, 48, 48, OK);
	TEST_DEL_KEY(Delete a key, 1, OK);
	TEST_DEL_KEY(Delete a key, 2, OK);
	TEST_DEL_KEY(Delete a key, 3, OK);
	TEST_DEL_KEY(Delete a key, 4, OK);
	TEST_GET_KEY(Is deleted, 3, 48, 48, -ENOKEY);
	ret = load_vm_key(&guest[0], savebuf, savebuf_size);
	if (ret == OK)
		printf("load_vm_keys OK\n");
	else
		printf("load_vm_keys FAIL\n");

	TEST_GET_KEY(Getkey after load 32B key, 1, 32, 32, OK);
	TEST_GET_KEY(Getkey after load 32B key, 2, 32, 32, OK);
	TEST_GET_KEY(Getkey after load 48B key, 3, 48, 48, OK);
	TEST_GET_KEY(Getkey after load 64B key, 4, 64, 64, OK);
	savebuf[savebuf_size-1]--;
	ret = load_vm_key(&guest[0], savebuf, savebuf_size);
	if (ret == -EINVAL)
		printf("load_vm_keys() if buffer is not valid OK\n");
	else
		printf("load_vm_keys() if buffer is not valid FAIL\n");
	savebuf_size--;
	ret = save_vm_key(&guest[0], savebuf, &savebuf_size);
	if (ret == -EINVAL)
		printf("save_vm_keys() if buffer size is too small OK\n");
	else

		printf("save_vm_keys() if buffer size is too small FAIL\n");



	return 0;
}
