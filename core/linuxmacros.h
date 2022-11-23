/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Kernel macro variants and constants
 */
#ifndef __LINUXMACROS__
#define __LINUXMACROS__

#include "hyp_config.h"
#include "hvccall-defines.h"
#include "host_defs.h"
#include <mmacros.S>

/*
 * Utility macros
 */
.macro adr_l dst, sym
	adrp	\dst, \sym
	add	\dst, \dst, :lo12:\sym
.endm

.macro save_clobber_regs
	stp	x0, x1, [sp, #(8 * 0)]
	stp	x2, x3, [sp, #(8 * 2)]
.endm

.macro	save_all_regs
	stp	x2, x3, [sp, #(8 * 2)]
	stp	x4, x5, [sp, #(8 * 4)]
	stp	x6, x7, [sp, #(8 * 6)]
	stp	x8, x9, [sp, #(8 * 8)]
	stp	x10, x11, [sp, #(8 * 10)]
	stp	x12, x13, [sp, #(8 * 12)]
	stp	x14, x15, [sp, #(8 * 14)]
	stp	x16, x17, [sp, #(8 * 16)]
	stp	x18, x19, [sp, #(8 * 18)]
	stp	x20, x21, [sp, #(8 * 20)]
	stp	x22, x23, [sp, #(8 * 22)]
	stp	x24, x25, [sp, #(8 * 24)]
	stp	x26, x27, [sp, #(8 * 26)]
	stp	x28, x29, [sp, #(8 * 28)]
	str	x30, [sp, #(8 * 30)]
.endm

.macro	load_all_regs
	ldp	x1, x2, [sp, #(8 * 1)]
	ldp	x3, x4, [sp, #(8 * 3)]
	ldp	x5, x6, [sp, #(8 * 5)]
	ldp	x7, x8, [sp, #(8 * 7)]
	ldp	x9, x10, [sp, #(8 * 9)]
	ldp	x11, x12, [sp, #(8 * 11)]
	ldp	x13, x14, [sp, #(8 * 13)]
	ldp	x15, x16, [sp, #(8 * 15)]
	ldp	x17, x18, [sp, #(8 * 17)]
	ldp	x19, x20, [sp, #(8 * 19)]
	ldp	x21, x22, [sp, #(8 * 21)]
	ldp	x23, x24, [sp, #(8 * 23)]
	ldp	x25, x26, [sp, #(8 * 25)]
	ldp	x27, x28, [sp, #(8 * 27)]
	ldp	x29, x30, [sp, #(8 * 29)]
.endm

.macro	save_callee_saved_regs ctxt
	str	x18, [\ctxt, #(8 * 18)]
	stp	x19, x20, [\ctxt, #(8 * 19)]
	stp	x21, x22, [\ctxt, #(8 * 21)]
	stp	x23, x24, [\ctxt, #(8 * 23)]
	stp	x25, x26, [\ctxt, #(8 * 25)]
	stp	x27, x28, [\ctxt, #(8 * 27)]
	stp	x29, x30, [\ctxt, #(8 * 29)]
.endm

.macro	restore_callee_saved_regs ctxt
	ldr	x18, [\ctxt, #(8 * 18)]
	ldp	x19, x20, [\ctxt, #(8 * 19)]
	ldp	x21, x22, [\ctxt, #(8 * 21)]
	ldp	x23, x24, [\ctxt, #(8 * 23)]
	ldp	x25, x26, [\ctxt, #(8 * 25)]
	ldp	x27, x28, [\ctxt, #(8 * 27)]
	ldp	x29, x30, [\ctxt, #(8 * 29)]
.endm

/*
 * Locate the fpsimd guest restore from the kernel
 * 0 is returned within /reg if fpsimd guest restore
 * is not installed.
 */
.macro get_fpsimd_guest_restore reg, tmp
	mov	\reg, #0
	adr	\tmp, __fpsimd_guest_restore
	ldr	\tmp, [\tmp]
	cmp	\tmp, #0
	b.eq	1f
	mov	\reg, #KERNEL_BASE
1:
	add     \reg, \reg, \tmp
.endm

/*
 * Here comes the fun, try to do what the kernel does.
 *
 */
.macro kern_hyp_va reg
	and	\reg, \reg, #CALL_MASK
	orr	\reg, \reg, #KERNEL_BASE
.endm

/*
 * Each cpu has the address of the kernel kvm_host_data
 * stored in an array. TIPDR_EL2 has a kvm_host_data
 * offset from the kernel mapping of the symbol to the
 * kernel linear mapping of the same symbol.
 *
 * Grab the core specific address, and add the symbols
 * kernel linear mapping offset found from tpidr_el2.
 * This should reverse the TIPDR setting by the kernel,
 * landing us with the address of the host data.
 */
.macro hyp_adr_this_cpu reg, sym, tmp
	smp_processor_id \tmp
	adr_l	\reg, \sym
	ldr	\reg, [\reg, \tmp, lsl #3]
	mrs	\tmp, tpidr_el2
	add	\reg, \reg, \tmp
.endm

/*
 * Adjust to context offset (if any)
 */
.macro get_host_ctxt reg, tmp
	hyp_adr_this_cpu \reg, __kvm_host_data, \tmp
	add	\reg, \reg, #HOST_DATA_CONTEXT		/* From asm-offsets.h */
.endm

/*
 * And finally pull the vcpu ptr from the context.
 */
.macro get_vcpu_ptr vcpu, ctxt
	get_host_ctxt	\ctxt, \vcpu			/* Get ctx kern addr */
	kern_hyp_va	\ctxt				/* Convert to hyp */
	ldr	\vcpu, [\ctxt, #HOST_CONTEXT_VCPU]	/* Get vcpu kern addr */
	kern_hyp_va	\vcpu				/* Convert to hyp */
.endm

#endif // __LINUXMACROS__
