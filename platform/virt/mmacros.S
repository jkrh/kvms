/* SPDX-License-Identifier: GPL-2.0-only */

#include "linuxmacros.h"
#include "pt_regs.h"

.macro smp_processor_id reg
	mrs	\reg, mpidr_el1
	ubfx	\reg, \reg, #0, #8
.endm

.macro platform_aarch64sync
	sub	sp, sp, #(PT_REGS_STACK_ALLOC)
	stp	x0, x1, [sp, #(8 * 0)]
	save_all_regs

	mov	x0, #1
	mov	x1, sp
	bl	dump_state
.endm
