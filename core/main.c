// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>

#include "platform_api.h"
#include "host_platform.h"
#include "hyplogs.h"
#include "armtrans.h"
#include "spinlock.h"
#include "bits.h"
#include "helpers.h"
#include "guest.h"
#include "hvccall.h"
#include "kentry.h"
#include "tables.h"
#include "heap.h"
#include "crypto/platform_crypto.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/memory_buffer_alloc.h"

struct mbedtls_entropy_context mbedtls_entropy_ctx;
struct mbedtls_ctr_drbg_context ctr_drbg;

uint8_t crypto_buf[PAGE_SIZE*2];
uint8_t key_heap[1024];
struct timeval tv1 ALIGN(16);
struct timeval tv2 ALIGN(16);
uint8_t init_index;

extern spinlock_t entrylock;
extern uint64_t __stack[];
extern uint64_t __fdt_addr;
extern uint64_t __lr_addr;

uint64_t __ret_addr;
uint64_t __stack_chk_guard;

static uint8_t *__my_sp;

int mbed_entropy(void *data, unsigned char *entropy, size_t len,
                 size_t *olen)
{
	int res;

	res = platform_entropy(entropy, len);
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

int early_setup(void)
{
	platform_early_setup();

	/* Exception vector */
	__asm__ __volatile__("adr	x0, __hyp_vectors\n"
			     "msr	VBAR_EL2, x0\n"
			     : : : "x0");

	return 0;
}

int crypto_init(void)
{
	int res;
	simd_t crypto_ctx;

	/* Platform reservation is not necessary here, but without it
	 * it gives unnecessary warning on debug build
	 */
	RESERVE_PLATFORM_CRYPTO(&crypto_ctx);
	mbedtls_memory_buffer_alloc_init(crypto_buf, sizeof(crypto_buf));
	mbedtls_entropy_init(&mbedtls_entropy_ctx);
	mbedtls_entropy_add_source(&mbedtls_entropy_ctx, mbed_entropy, NULL, 8,
				    MBEDTLS_ENTROPY_SOURCE_STRONG);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
				    &mbedtls_entropy_ctx, 0, 0);
	RESTORE_PLATFORM_CRYPTO(&crypto_ctx);
	if (res)
		panic("mbedtls_ctr_drbg_seed returned %d\n", res);

	return 0;
}

void enter_el1_cold(void)
{
	kernel_func_t *start_addr;
	kvm_guest_t *guest;
	uint64_t vmid, core_index;
	uint8_t *stack;

	core_index = smp_processor_id();
	vmid = get_current_vmid();
	guest = get_guest(vmid);
	start_addr = guest->cpu_map[core_index];

	if (!start_addr)
		start_addr = (kernel_func_t *)__ret_addr;

	stack = platfrom_get_stack_ptr(core_index);
	__enter_el1_cold(start_addr, (void *)stack);
}

void enter_el1_warm(kernel_func_t *entry_addr)
{
	uint64_t core_index;
	uint8_t *stack;

	core_index = smp_processor_id();
	stack = platfrom_get_stack_ptr(core_index);
	__enter_el1_warm(entry_addr, (void *)stack);
	panic("");
}

void hyp_warm_entry(uint64_t core_index)
{
	kvm_guest_t *host;

	early_setup();
	enable_mmu();
	host = get_guest(HOST_VMID);

	core_index = smp_processor_id();
	enter_el1_warm(host->cpu_map[core_index]);
}

void __stack_chk_guard_setup(void)
{
	__stack_chk_guard = 0xBADC0DE;
}

void __stack_chk_fail(void)
{
	panic("stack check failed\n");
}

int main(int argc UNUSED, char **argv UNUSED)
{
	kvm_guest_t *host;
	int res;

	__asm__ __volatile__("str	x26, %[__lr_addr]\n"
			     "str	x27, %[__ret_addr]\n"
			     "str	x28, %[__fdt_addr]\n"
			     :
			     : [__ret_addr] "m"(__ret_addr),
			       [__fdt_addr] "m"(__fdt_addr),
			       [__lr_addr] "m"(__lr_addr)
			     : "memory");

	init_index = smp_processor_id();
	gettimeofday(&tv1, NULL);
	platform_console_init();

	if (init_index == 0) {
		log_init();
		init_guest_array();
		if (HOST_VMID == 0)
			panic("");
		host = get_free_guest(HOST_VMID);
		if (!host)
			panic("");
		tdinfo_init();
		table_init();
		res = machine_init(host);
		set_heap(key_heap, sizeof(key_heap));
		if (res)
			return res;
	} else {
		__my_sp = platfrom_get_stack_ptr(init_index);
		__asm__ __volatile__("mov	sp, %[__my_sp]\n"
				     :
				     : [__my_sp] "r"(__my_sp)
				     :);
	}
	/*
	 * Note: we may have just swapped stack ^
	 */
	early_setup();
	enable_mmu();
	/*
	 * Things that need to initialize that require unaligned accesses
	 * go here.
	 */
	if (init_index == 0) {
		if (crypto_init() != 0)
			panic("crypto init failed\n");
	}
	gettimeofday(&tv2, NULL);
	LOG("HYP: core %ld initialization latency was %ldms\n",
	     init_index, (tv2.tv_usec - tv1.tv_usec) / 1000);
	init_index++;
	spin_unlock(&entrylock);

	enter_el1_cold();
	panic("end of main reached\n");
	return -EFAULT;
}
