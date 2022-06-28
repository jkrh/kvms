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

int set_heap(void *h, size_t sz);

kvm_guest_t guest[4];
uint8_t crypto_buf[1024];

struct mbedtls_entropy_context mbedtls_entropy_ctx;
struct mbedtls_ctr_drbg_context ctr_drbg;
static uint8_t heap[1024];

typedef uint8_t keys_t[32];

int mbed_entropy(void *data, unsigned char *entropy, size_t len,
		 size_t *olen)
{
	int res;

	res = 0;// platform_entropy(entropy, len);
	if (!res)
		*olen = len;
	else
		*olen = 0;

	return 0;
}

int mbedtls_hardware_poll(void *data, unsigned char *entropy, size_t len,
			  size_t *olen)
{
	return mbed_entropy(data, entropy, len, olen);
}

void hexdump(uint8_t *p, uint32_t len)
{
	int i = 0;

	printf("(%d)\n", len);
	while (len--) {
		printf("%02x ", *p++);
		if ((++i % 32) == 0)
			printf("\n");
	}
	printf("\n");
}

void pr_error(char *txt, uint8_t *b1, uint8_t *b2)
{
	printf("Error %s\n", txt);
	hexdump(b1, 32);
	hexdump(b2, 32);
}
void checkret(char *txt, int ret, int exp)
{
	if (ret == exp) {
		printf("%s OK\n", txt);
	} else {
		printf("%s FAIL, expected %d, actual : %d\n", txt, exp, ret);
	}
}

int checkkey(uint8_t *a, uint8_t *b, uint32_t len)
{
	int ret = memcmp(a, b, len);

	if (ret == 0) {
		memset(b, 0, len);
	}
	return ret;
}

int main(void)
{
	size_t savebuf_size = 1024;
	keys_t keys[9];
	keys_t tmp;
	size_t bufsize = 32;
	uint8_t buf[32];
	uint8_t savebuf[1024];
	const uint8_t guest_id[] = "test22test";
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
	ret = set_guest_id(guest, guest_id, sizeof(guest_id));

	guest[0].keybuf = NULL;
	ret = generate_key(&guest[0], keys[0], &bufsize, AES256, "test0");
	checkret("generate_key() 0", ret, 0);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test0");
	checkret("get_key() 0", ret, 0);
	if (checkkey(keys[0], buf, 32))
		pr_error("keys0", keys[0], buf);

	ret = generate_key(&guest[0], keys[1], &bufsize, AES256, "test1");
	checkret("generate_key() 1", ret, 0);
	ret = generate_key(&guest[0], keys[2], &bufsize, AES256, "test2");
	checkret("generate_key() 2", ret, 0);
	ret = generate_key(&guest[0], keys[3], &bufsize, AES256, "test3");
	checkret("get_key() 3", ret, 0);

	ret = get_key(&guest[0], buf, &bufsize, AES256, "test2");
	checkret("get_key() 2", ret, 0);
	if (checkkey(keys[2], buf, 32))
		pr_error("keys2", keys[2], buf);

	ret = generate_key(&guest[0], keys[2], &bufsize, AES256, "test2");
	checkret("generate_key() 2", ret, 0);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test2");
	checkret("get_key() 2", ret, 0);
	if (checkkey(keys[2], buf, 32))
		pr_error("get_key() 2", keys[2], buf);

	ret = delete_key(&guest[0], AES256, "test2");
	checkret("delete_key() 2", ret, 0);

	ret = get_key(&guest[0], buf, &bufsize, AES256, "test2");
	checkret("get_key() 2", ret, -ENOKEY);

	ret = generate_key(&guest[0], keys[2], &bufsize, AES256, "test2");
	checkret("generate_key() 2", ret, 0);

	ret = get_key(&guest[0], buf, &bufsize, AES256, "test2");
	checkret("get_key() 2", ret, 0);
	if (checkkey(keys[2], buf, 32))
		pr_error("keys2", keys[2], buf);

	ret = delete_key(&guest[0], AES256, "test0");
	checkret("delete_key() 0", ret, 0);

	ret = get_key(&guest[0], buf, &bufsize, AES256, "test2");
	checkret("get_key() 2", ret, 0);
	if (checkkey(keys[2], buf, 32))
		pr_error("keys2", keys[2], buf);

	ret = get_key(&guest[0], buf, &bufsize, AES256, "test0");
	checkret("get_key() 0", ret, -ENOKEY);

	ret = generate_key(&guest[0], keys[3], &bufsize, AES256, "test3");
	checkret("generate_key() 3", ret, 0);
	ret = generate_key(&guest[0], keys[4], &bufsize, AES256, "test4");
	checkret("generate_key() 4", ret, 0);
	ret = generate_key(&guest[0], keys[5], &bufsize, AES256, "test5");
	checkret("generate_key() 5", ret, 0);

	ret = get_key(&guest[0], buf, &bufsize, AES256, "test3");
	checkret("get_key() 3", ret, 0);
	if (checkkey(keys[3], buf, 32))
		pr_error("get_key() 3", keys[3], buf);

	ret = get_key(&guest[0], buf, &bufsize, AES256, "test5");
	checkret("get_key() 5", ret, 0);
	if (checkkey(keys[5], buf, 32))
		pr_error("get_key() 5", keys[5], buf);

	ret = delete_key(&guest[0], AES256, "test5");
	checkret("delete_key() 5", ret, 0);

	ret = save_vm_key(&guest[0], savebuf, &savebuf_size);
	checkret("save buf", ret, 0);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test5");
	checkret("get_key() 5", ret, -ENOKEY);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test4");
	checkret("get_key() 4", ret, 0);
	if (checkkey(keys[4], buf, 32))
		pr_error("keys4", keys[4], buf);
	ret = generate_key(&guest[0], keys[6], &bufsize, AES256, "test6");
	checkret("generate_key() 6", ret, 0);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test6");
	checkret("get_key() 6", ret, 0);
	if (checkkey(keys[6], buf, 32))
		pr_error("keys6", keys[6], buf);

	ret = delete_key(&guest[0], AES256, "test6");
	checkret("delete_key() 6", ret, 0);
	ret = delete_key(&guest[0], AES256, "test4");
	checkret("delete_key() 4", ret, 0);
	ret = delete_key(&guest[0], AES256, "test3");
	checkret("delete_key() 3", ret, 0);
	ret = delete_key(&guest[0], AES256, "test2");
	checkret("delete_key() 2", ret, 0);
	ret = delete_key(&guest[0], AES256, "test1");
	checkret("delete_key() 1", ret, 0);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test1");
	checkret("get_key() 1", ret, -ENOKEY);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test2");
	checkret("get_key() 2", ret, -ENOKEY);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test3");
	checkret("get_key() 3", ret, -ENOKEY);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test4");
	checkret("get_key() 4", ret, -ENOKEY);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test5");
	checkret("get_key() 5", ret, -ENOKEY);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test6");
	checkret("get_key() 6", ret, -ENOKEY);
	ret = generate_key(&guest[0], keys[0], &bufsize, AES256, "test0");
	checkret("generate_key() 0", ret, 0);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test0");
	checkret("get_key() 0", ret, 0);
	ret = generate_key(&guest[0], tmp, &bufsize, AES256, "test1");
	checkret("generate_key() 0", ret, 0);
	ret = load_vm_key(&guest[0], savebuf, savebuf_size);
	checkret("load keys", ret, 0);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test0");
	checkret("get_key() 0", ret, 0);
	if (checkkey(keys[0], buf, 32))
		pr_error("keys0", keys[0], buf);
	ret = get_key(&guest[0], buf, &bufsize, AES256, "test1");
	checkret("get_key() 1", ret, 0);
	if (checkkey(keys[1], buf, 32))
		pr_error("key1", keys[1], buf);

	ret = get_key(&guest[0], buf, &bufsize, AES256, "test2");
	checkret("get_key() 2", ret, 0);
	if (checkkey(keys[2], buf, 32))
		pr_error("keys2", keys[2], buf);

	ret = get_key(&guest[0], buf, &bufsize, AES256, "test3");
	checkret("get_key() 3", ret, 0);
	if (checkkey(keys[3], buf, 32))
		pr_error("keys3", keys[3], buf);

	ret = get_key(&guest[0], buf, &bufsize, AES256, "test4");
	checkret("get_key() 4", ret, 0);
	if (checkkey(keys[4], buf, 32))
		pr_error("keys4", keys[4], buf);

	return 0;
}
