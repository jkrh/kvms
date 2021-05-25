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

extern uint64_t entrylock;
extern uint64_t __stack[];
extern uint64_t __fdt_addr;
extern uint64_t __lr_addr;

uint64_t __ret_addr;
uint64_t __stack_chk_guard;

static uint8_t *__my_sp;

int early_setup(void)
{

	platform_early_setup();

	/* Exception vector */
	__asm__ __volatile__("adr	x0, __hyp_vectors\n"
			     "msr	VBAR_EL2, x0\n"
			     : : : "x0");

	return 0;
}

NORETURN
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

	HYP_ABORT();
	while(1)
		wfi();
}

void enter_el1_warm(kernel_func_t *entry_addr)
{
	uint64_t core_index;
	uint8_t *stack;

	core_index = smp_processor_id();
	stack = platfrom_get_stack_ptr(core_index);
	__enter_el1_warm(entry_addr, (void *)stack);

	HYP_ABORT();
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
	HYP_ABORT();
}

int main(int argc UNUSED, char **argv UNUSED)
{
	struct timeval tv;
	uint64_t init_index;
	int res;
	kvm_guest_t *host;

	__asm__ __volatile__("str	x26, %[__lr_addr]\n"
			     "str	x27, %[__ret_addr]\n"
			     "str	x28, %[__fdt_addr]\n"
			     :
			     : [__ret_addr] "m"(__ret_addr),
			       [__fdt_addr] "m"(__fdt_addr),
			       [__lr_addr] "m"(__lr_addr)
			     : "memory");

	init_index = smp_processor_id();
	gettimeofday(&tv, NULL);
	platform_console_init();
	LOG("HYP: core %d started at %ldus\n", init_index, tv.tv_usec);

	if (init_index == 0) {
		tdinfo_init();
		table_init();
		host = get_guest(HOST_VMID);
		if (!host)
			HYP_ABORT();
		res = machine_init(host);
		if (res)
			return res;
	} else {
		__my_sp = platfrom_get_stack_ptr(init_index);
		__asm__ __volatile__("mov	sp, %[__my_sp]\n"
				     :
				     : [__my_sp] "r"(__my_sp)
				     :);
	}
	early_setup();
	enable_mmu();

	gettimeofday(&tv, NULL);
	LOG("HYP: core %d entering el1 at %ldus\n", init_index, tv.tv_usec);
	init_index++;
	spin_unlock(&entrylock);

	enter_el1_cold();
}
