#
# SPDX-License-Identifier: GPL-2.0-only
#
#include "hvccall-defines.h"
#include "psci.h"
#
# Input
# ------
# MMU = off, D-cache = off, I-cache = on or off
# CPU in EL1
# x0 : device tree address from VMM
# x1 : original guest start address from HYP

.global _start
_start:
	adr x29, .stack_top
	mov sp, x29
	sub sp, sp, #(8 * 4)
	stp x0, x1, [sp, #(8 * 0)]
	stp x2, x3, [sp, #(8 * 2)]

	/* remap loader to final address */
	adr x1, _start
	mov x0, #HYP_GUEST_REMAP_LOADER
	hvc #0
	cbnz x0, err_handler

	/* reinit the stack pointer on final address */
	adr x29, .stack_top
	mov sp, x29
	sub sp, sp, #(8 * 4)
	ldp x0, x1, [sp, #(8 * 0)]

	/* ic_loader cal modify registers contents on the stack */
	mov x0, sp
	bl ic_loader

	mov x4, xzr
	mov x5, xzr
	mov x6, xzr
	mov x7, xzr
	mov x8, xzr
	mov x9, xzr
	mov x10, xzr
	mov x11, xzr
	mov x12, xzr
	mov x13, xzr
	mov x14, xzr
	mov x15, xzr
	mov x16, xzr
	mov x17, xzr
	mov x18, xzr
	mov x19, xzr
	mov x20, xzr
	mov x21, xzr
	mov x22, xzr
	mov x23, xzr
	mov x24, xzr
	mov x25, xzr
	mov x26, xzr
	mov x27, xzr
	mov x28, xzr
	mov x29, xzr
	ldp	x0, x1, [sp, #(8 * 0)]

	br x1
