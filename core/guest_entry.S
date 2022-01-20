/* SPDX-License-Identifier: GPL-2.0-only */
#include "linuxmacros.h"
#include "pt_regs.h"

	.global	hyp_guest_enter
	.global	guest_exit

/*
 * uint64_t hyp_guest_enter(void *vcpu, struct user_pt_regs *regs);
 *  x0: kern_hyp_va(vcpu)
 *  x1: guest regs
 */
hyp_guest_enter:
	get_host_ctxt	x2, x3
	kern_hyp_va	x2
	save_callee_saved_regs	x2

	mov	x3, sp
	str	x3, [x2, #CPU_HOST_SP]

	mrs	x3, sp_el0
	str	x3, [x2, #(8 * 31)]

	mrs	x3, ISR_EL1
	cbz	x3, 1f
	mov	x0, #ARM_EXCEPTION_IRQ
	ret

1:	str	x0, [x2, #HOST_CONTEXT_VCPU]
	add	x0, x0, #VCPU_CONTEXT
	ldr	x2, [x0, #(8 * 31)]
	msr	sp_el0, x2
	mov	x29, x1
	ldp	x0, x1,   [x29, #(8 * 0)]
	ldp	x2, x3,   [x29, #(8 * 2)]
	ldp	x4, x5,   [x29, #(8 * 4)]
	ldp	x6, x7,   [x29, #(8 * 6)]
	ldp	x8, x9,   [x29, #(8 * 8)]
	ldp	x10, x11, [x29, #(8 * 10)]
	ldp	x12, x13, [x29, #(8 * 12)]
	ldp	x14, x15, [x29, #(8 * 14)]
	ldp	x16, x17, [x29, #(8 * 16)]
	restore_callee_saved_regs x29

	eret
	dsb	nsh
	isb

guest_exit:
	mrs	x0, VTTBR_EL2
	lsr	x0, x0, #48
	get_vcpu_ptr	x1, x2
	ldr	x1, [x1, #VCPU_VCPUIDX]
	mov	x2, x18
	mov	x3, sp
	bl	guest_exit_prep
	add	sp, sp, #(PT_REGS_SIZE)

	get_vcpu_ptr	x1, x0
	add	x1, x1, #VCPU_CONTEXT
	mrs	x0, sp_el0
	str	x0, [x1, #(8 * 31)]
	get_host_ctxt	x2, x3
	kern_hyp_va	x2
	ldr	x3, [x2, #(8 * 31)]
	msr	sp_el0, x3
	mov	x0, x19
	restore_callee_saved_regs x2
	ldr	x3, [x2, #CPU_HOST_SP]
	mov	sp, x3

	get_host_ctxt	x2, x3
	kern_hyp_va	x2
	str	xzr, [x2, #HOST_CONTEXT_VCPU]

	dsb	sy
	isb
	mrs	x2, ISR_EL1
	tbnz	x2, #8, 1f
	ret

1:
	mrs	x2, ELR_EL2
	mrs	x3, ESR_EL2
	mrs	x4, SPSR_EL2
	mov	x5, x0

	msr	daifclr, #4

	isb

	msr	daifset, #4
	ret
