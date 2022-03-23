/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/aes.h"

static int mode;
typedef struct {
	uint8_t *key;
	uint8_t *plaintext;
	uint8_t *ciphertext;
	int textlen;
	int mode;
} test_data_t;

/* dummy  mbedtls_hardware_poll() for testing */
int mbedtls_hardware_poll(void *data, unsigned char *entropy, size_t len,
			  size_t *olen)
{
	return 1234;
}

/* dummy smp_processor_id() for testing */
int smp_processor_id(void)
{
	return 0;
}

static void hexdump(unsigned char *c, int len)
{
	for (int i = 0; i < len; i++)
		printf("%02x ", c[i]);
	printf("\n");
}


static int str2bin(uint8_t *b, char *str)
{
	int tmp;
	int i = 0;

	while (*str) {
		if (sscanf(str, "%2x", &tmp) == 1) {
			b[i++] = (unsigned char) tmp;
		}
		str += 2;
	}
	return i;
}

static char *strstr2(const char *h, const char *i)
{
	return strstr(h, i) + strlen(i);
}

void free_test_data(test_data_t test_data)
{
	free(test_data.key);
	free(test_data.ciphertext);
	free(test_data.plaintext);
}

static int seek_to_next_test(FILE *fp)
{
	size_t size = 0;
	char *buf = NULL;
		while (getline(&buf, &size, fp) != -1) {
		if (strstr(buf, "[ENCRYPT]"))
			mode = MBEDTLS_AES_ENCRYPT;
		if (strstr(buf, "[DECRYPT]"))
			mode = MBEDTLS_AES_DECRYPT;
		if (strstr(buf, "COUNT =")) {
			free(buf);
			return 1;
		}
	}
	free(buf);
	return 0;
}

static int get_next_test(FILE *fp, test_data_t *test_data)
{
	size_t size = 0;
	ssize_t  len;

	char *buf = NULL;
	uint8_t *data = NULL;
	int datalen;

	if (seek_to_next_test(fp)) {
		while ((len = getline(&buf, &size, fp) > 4)) {
			data = malloc(strlen(buf) / 2);
			if (!data)
				exit(1);
			datalen = str2bin(data, strstr2(buf, " = "));
			if (strstr(buf, "KEY"))
				test_data->key = data;
			if (strstr(buf, "PLAINTEXT"))
				test_data->plaintext = data;
			if (strstr(buf, "CIPHERTEXT")) {
				test_data->ciphertext = data;
				test_data->textlen = datalen;
				test_data->mode = mode;
			}

		}
		free(buf);
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int failed = 0;
	int test = 0;
	FILE *fp;
	uint8_t outdata[32];
	uint8_t *cmp;
	test_data_t test_data;
	mbedtls_aes_context ctx;

	if (argc != 2) {
		printf("Usage:%s nist_test_vectors_file.rsp\n", argv[0]);
		printf("(ECB*256.rsp)\n");
		printf("Use \"make test_vectors\" to download them\n");
		return -1;
	}

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		printf("Cannot open test vectors file\n");
		return -1;
	}
	while (get_next_test(fp, &test_data)) {
		if (test_data.mode == MBEDTLS_AES_ENCRYPT) {
			cmp = test_data.ciphertext;
			mbedtls_aes_setkey_enc(&ctx, test_data.key, 256);
			mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, test_data.plaintext, outdata);
		} else {
			cmp = test_data.plaintext;
			mbedtls_aes_setkey_dec(&ctx, test_data.key, 256);
			mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, test_data.ciphertext, outdata);
		}
		if (memcmp(cmp, outdata, 16)) {
			failed = 1;
			printf("Test failed!\n");
			printf("The output of AES is: ");
			hexdump(outdata, 16);
			printf("The output shuold be: ");
			hexdump(cmp, 16);
		}
		test++;
		free_test_data(test_data);
	}
	if (!failed)
		printf("All tests (%d) passed\n", test);

	return failed;
}
