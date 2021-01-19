/* SPDX-License-Identifier: GPL-2.0-only */
.macro clean_all_regs
	mov	x0, #0
	mov	x1, #0
	mov	x2, #0
	mov	x3, #0
	mov	x4, #0
	mov	x5, #0
	mov	x6, #0
	mov	x7, #0
	mov	x8, #0
	mov	x9, #0
	mov	x10, #0
	mov	x11, #0
	mov	x12, #0
	mov	x13, #0
	mov	x14, #0
	mov	x15, #0
	mov	x16, #0
	mov	x17, #0
	mov	x18, #0
	mov	x19, #0
	mov	x20, #0
	mov	x21, #0
	mov	x22, #0
	mov	x23, #0
	mov	x24, #0
	mov	x25, #0
	mov	x26, #0
	mov	x27, #0
	mov	x28, #0
	mov	x29, #0
	mov	x30, #0
.endm

.global __enter_el1_cold
.type __enter_el1_cold, %function
__enter_el1_cold:
	msr	elr_el2, x0
	mov	x0, #0x3c5
	msr	spsr_el2, x0
	clean_all_regs
	adr	x21, __fdt_addr
	ldr	x21, [x21]
	adr	x30, __lr_addr
	ldr	x30, [x30]
	eret

.global __enter_el1_warm
.type __enter_el1_warm, %function
__enter_el1_warm:
	msr	elr_el2, x0
	mov	x0, #0x3c5
	msr	spsr_el2, x0
	clean_all_regs
	eret
