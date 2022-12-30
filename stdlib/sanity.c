/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdint.h>

#include "hyplogs.h"
#include "commondefines.h"

uint64_t __stack_chk_guard;

struct type_descriptor {
	uint16_t type_kind;
        uint16_t type_info;
        char type_name[1];
};

struct source_location {
	const char *file_name;
	union {
		unsigned long reported;
		struct {
			uint32_t line;
			uint32_t column;
		};
	};
};

struct type_mismatch_data_v1 {
	struct source_location location;
	struct type_descriptor *type;
	unsigned char log_alignment;
	unsigned char type_check_kind;
};

const char *type_check_kinds[] = {
	"load of",
	"store to",
	"reference binding to",
	"member access within",
	"member call on",
	"constructor call on",
	"downcast of",
	"downcast of",
	"upcast of",
	"cast to virtual base of",
};

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

void __ubsan_handle_type_mismatch_v1(struct type_mismatch_data_v1 *type_mismatch,
				     uintptr_t pointer)
{
	const char *type_kind;

	if (pointer == 0)
		panic("null pointer access\n");

	if (type_mismatch == NULL)
		panic("no type mismatch data\n");

	if (type_mismatch->log_alignment != 0 &&
	    is_aligned(pointer, type_mismatch->log_alignment)) {
		panic("unaligned memory access\n");
	} else {
		if (type_mismatch->type_check_kind < (sizeof(type_check_kinds)/sizeof(const char *)))
			type_kind = type_check_kinds[type_mismatch->type_check_kind];
		else
			type_kind = "unknown action at";

		panic("%s address %p with insufficient space for object of type %s\n",
		      type_kind, (void *)pointer, type_mismatch->type->type_name);
	}
	panic("unknown type mismatch cause\n");
}
