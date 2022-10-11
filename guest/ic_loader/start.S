#
# SPDX-License-Identifier: GPL-2.0-only
#
# Input
# ------
# MMU = off, D-cache = off, I-cache = on or off
# CPU in EL1
# x0 - x3 : Parameters from qemu kernel loader

.global _start
_start:
	adr x29, .stack_top
	mov sp, x29
	sub sp, sp, #(8 * 6)
	str x0, [sp, #(8 * 0)]
	str x1, [sp, #(8 * 1)]
	str x2, [sp, #(8 * 2)]
	str x3, [sp, #(8 * 3)]
	subs x30, x30, #4
	str x30, [sp, #(8 * 4)]
	mov x0, x30
	bl ic_loader
	cmp x0, #0
	beq ok
# execute undef instruction, exit from guest
.quad   0x000000000000

ok:
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
	ldr x0, [sp, #(8 * 0)]
	ldr x1, [sp, #(8 * 1)]
	ldr x2, [sp, #(8 * 2)]
	ldr x3, [sp, #(8 * 3)]
	ldr x30, [sp, #(8 * 4)]
	br lr
