/* SPDX-License-Identifier: GPL-2.0-only */
#include "hyplogs.h"

uint64_t __stack_chk_guard;

void __stack_chk_guard_setup(void)
{
	__stack_chk_guard = 0xBADC0DE;
}

void __stack_chk_fail(void)
{
	panic("stack check failed\n");
}

void __ubsan_handle_add_overflow(void)
{
	panic("add overflow\n");
}

void __ubsan_handle_sub_overflow(void)
{
	panic("sub overflow\n");
}

void __ubsan_handle_mul_overflow(void)
{
	panic("multiplication overflow\n");
}

void __ubsan_handle_negate_overflow(void)
{
	panic("negate overflow\n");
}

void __ubsan_handle_out_of_bounds(void)
{
	panic("out of bounds\n");
}

void __ubsan_handle_pointer_overflow(void)
{
	panic("pointer overflow\n");
}

void __ubsan_handle_type_mismatch_v1(void)
{
	panic("type mismatch\n");
}
