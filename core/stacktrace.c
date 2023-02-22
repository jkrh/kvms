// SPDX-License-Identifier: GPL-2.0-only

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>

#include "hyplogs.h"
#include "helpers.h"
#include "kallsyms.h"
#include "stacktrace.h"
#include "platform_api.h"

static inline bool on_accessible_stack(unsigned long sp)
{
	unsigned long low;
	unsigned long high;

	high = (unsigned long)platfrom_get_stack_ptr(smp_processor_id());
	low = high - STACK_SIZE;
	if (sp < low || sp >= high) {
		return false;
	}
	return true;
}

/*
 * AArch64 PCS assigns the frame pointer to x29.
 *
 * A simple function prologue looks like this:
 *      sub     sp, sp, #0x10
 *      stp     x29, x30, [sp]
 *      mov     x29, sp
 *
 * A simple function epilogue looks like this:
 *      mov     sp, x29
 *      ldp     x29, x30, [sp]
 *      add     sp, sp, #0x10
 */
int unwind_frame(struct stackframe *frame)
{
	unsigned long fp = frame->fp;

	if (fp & 0xf)
		return -EINVAL;

	if (!on_accessible_stack(fp)) {
		return -EINVAL;
	}

	frame->fp = *(unsigned long *)(fp);
	frame->pc = *(unsigned long *)(fp + 8);

	/*
	 * Frames created upon entry from EL0 have NULL FP and PC values, so
	 * don't bother reporting these. Frames created by __noreturn functions
	 * might have a valid FP even if PC is bogus, so only terminate where
	 * both are NULL.
	 */
	if (!frame->fp && !frame->pc)
		return -EINVAL;

	return 0;
}

static void dump_stack_print_info(int log_lvl)
{
	logf(log_lvl, "CPU: %d VMID: %d\n", smp_processor_id(),
	      get_current_vmid());
}

static void dump_backtrace_entry(int log_lvl, unsigned long where)
{
	char sym[KSYM_SYMBOL_LEN];

	sprint_symbol(sym, where);
	logf(log_lvl, " %s\n", sym);
}

void dump_backtrace(int log_lvl, struct stackframe *sf)
{
	struct stackframe frame;

	if (!sf) {
		frame.fp = (unsigned long)__builtin_frame_address(0);
		frame.pc = (unsigned long)dump_backtrace;
	} else {
		frame.fp = sf->fp;
		frame.pc = sf->pc;
	}

	logf(log_lvl, "Call trace:\n");
	do {
		if (!is_ksym_addr(frame.pc))
			break;
		dump_backtrace_entry(log_lvl, frame.pc);
	} while (!unwind_frame(&frame));
}

void __dump_stack(int log_lvl)
{
	dump_stack_print_info(log_lvl);
	dump_backtrace(log_lvl, NULL);
}
