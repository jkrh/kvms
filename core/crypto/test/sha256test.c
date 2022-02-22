/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include "mbedtls/platform.h"
#include "platform_crypto.h"

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

static char *find_data(FILE *fp, char *buf, const char *id)
{
	size_t len = 8192;
	char *p;
	int x;

	while ((x = getline(&buf, &len, fp)) != -1) {
		p = strstr(buf, id);
		if (p) {
			return buf;
		}
	}
	return NULL;
}

static char *strstr2(const char *h, const char *i)
{
	return strstr(h, i) + strlen(i);
}

static int get_msg(FILE *fp, char *buf, uint8_t *out)
{
	int size;
	char *p = find_data(fp, buf, "Len =");

	if (p == NULL)
		return -1;

	size = str2bin(out, strstr2(p, "Len = "));
	if ((out[0] == 0) && (size == 1)) {
		return 0;
	}
	p = find_data(fp, buf, "Msg =");
	if (p == NULL)
		return -1;
	return str2bin(out, strstr2(p, "Msg = "));
}

static int get_hash(FILE *fp, char *buf, uint8_t *out)
{
	char *p = find_data(fp, buf, "MD =");

	if (p == NULL)
		return -1;
	return str2bin(out, strstr2(p, "MD = "));
}

int main(int argc, char *argv[])
{
	char *buf = NULL;
	uint8_t msg[8192];
	uint8_t md[64];
	uint8_t hash[32];
	mbedtls_sha256_context ctx;
	int passed = 1;
	int msg_len;
	int hash_len;
	int test = 0;
	FILE *fp;

	if (argc != 2) {
		printf("Usage:%s nist_test_vectors_file.rsp\n", argv[0]);
		printf("nist_test_vectors_file (iSHA256LongMsg.rsp or SHA256ShortMsg.rsp)");
		printf("can be down loaded from:\n");
		printf("https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabittestvectors.zip");
		return -1;
	}

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		printf("Cannot open test vectors file\n");
		return -1;
	}

	while ((msg_len = get_msg(fp, buf, msg)) >= 0) {
		hash_len = get_hash(fp, buf, md);
		mbedtls_sha256_starts_ret(&ctx, 0);
		mbedtls_sha256_update_ret(&ctx, msg, msg_len);
		mbedtls_sha256_finish_ret(&ctx, hash);
		if (memcmp(hash, md, hash_len)) {
			passed = 0;
			printf("Test Failed!\n");
			printf("msg:");
			hexdump(msg, msg_len);
			printf("Calculated:    ");
			hexdump(hash, hash_len);
			printf("Correct value: ");
			hexdump(md, hash_len);
		} else
			test++;
	}

	if (passed)
		printf("All tests (%d) passed\n", test);

	return 0;
}
