// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "guest.h"
#include "keystore.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/sha256.h"

#include <stdarg.h>
#include<stdio.h>

typedef struct kvm_guest kvm_guest_t;
#define BUFSIZE 128

int  kernel_integrity_ok(const kvm_guest_t *guest)
{
	return true;
}
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

void __ubsan_handle_type_mismatch_v1(void) {}
void __ubsan_handle_out_of_bounds(void) {}
void __ubsan_handle_add_overflow(void){}
void __ubsan_handle_sub_overflow(void) {}
void __ubsan_handle_mul_overflow(void) {}
void spin_lock(spinlock_t *lock) {}
void spin_unlock(spinlock_t *lock) {}

int platform_get_platform_key(uint8_t *key, size_t key_size,
			      void *salt, size_t salt_len)
{
	int i;
	for (i = 0; i < key_size; i++)
		key[i] = i;
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

int copy_from_guest(kvm_guest_t *guest, uint64_t stage, void *dst, const void *src, size_t len)
{
	memcpy(dst, src, len);
	return 0;
}
int copy_to_guest(kvm_guest_t *guest, uint64_t stage, void *dst, void *src, size_t len)
{
	memcpy(dst, src, len);
	return 0;
}

int platform_get_static_key(uint8_t *key, size_t key_size,
			      void *salt, size_t salt_len)
{
	int i;

	for (i = 0; i < key_size; i++)
		key[i] = i;
	return 0;
}
static int __printbuf(char *buf)
{
	int count = 0;

	buf[BUFSIZE - 1] = '\0';
	while (buf[count]) {
		if (putchar(buf[count]) != EOF) {
			count++;
		} else {
			count = EOF;
			break;
		}
	}

	return count;
}
void __log(int level, const char *func, const char *fmt, ...)
{
	char buf[BUFSIZE];
	struct timeval tv2;
	va_list args;

	gettimeofday(&tv2);

	if (level)
		printf("\033[0;31m");

	printf("[%*.*lu] %*.*s ", 12, 12, us_to_ms(tv2.tv_usec), 20, 20, func);
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	va_end(args);

	__printbuf(buf);
	putchar('\r');

	if (level)
		printf("\033[0m");
}
