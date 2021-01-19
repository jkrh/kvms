/* SPDX-License-Identifier: GPL-2.0-only */
#include <mmacros.S>
#include <host_defs.h>

#include "linuxmacros.h"

.macro ventry target
	.rept 31
	nop
	.endr
	b	\target
.endm

	.text
	.align 11

.macro invalid_vector label
\label:
	b 	\label
.endm

__hyp_vectors:
	.global __hyp_vectors

	ventry  el2_sync_invalid	// Synchronous EL2t
	ventry  el2_irq_invalid		// IRQ EL2t
	ventry  el2_fiq_invalid		// FIQ EL2t
	ventry  el2_error_invalid	// Error EL2t

	ventry  el2_sync		// Synchronous EL2h
	ventry  el2_irq_invalid		// IRQ EL2h
	ventry  el2_fiq_invalid		// FIQ EL2h
	ventry  el2_error_invalid	// Error EL2h

	ventry  el1_sync		// Synchronous 64-bit EL1
	ventry  el1_irq			// IRQ 64-bit EL1
	ventry  el1_fiq_invalid		// FIQ 64-bit EL1
	ventry  el1_error		// Error 64-bit EL1

	ventry  el1_sync_invalid	// Synchronous 32-bit EL1
	ventry  el1_irq_invalid		// IRQ 32-bit EL1
	ventry  el1_fiq_invalid		// FIQ 32-bit EL1
	ventry  el1_error_invalid	// Error 32-bit EL1

el1_sync:
	msr	SPSel, #1

	sub	sp, sp, #(8 * 36)
	save_all_regs

	mrs	x1, ESR_EL2
	and	x1, x1, #0xFC000000
	asr	x1, x1, #26
	cmp	x1, #0x20		// Inst abort
	beq	el1_trap
	cmp	x1, #0x24		// Data abort
	beq	el1_trap
	cmp	x1, #0x01		// WFI/WFE
	beq	el1_trap
	cmp	x1, #0x07		// SVE, SIMD, FP
	beq	fpsimd_trap
	cmp	x1, #0x17		// SMC
	beq	smc_trap
	cmp	x1, #0x18		// Debug trap
	beq	el1_trap
	cmp	x1, #0x32		// Software step
	beq	el1_trap
	cmp	x1, #0x31		// Breakpoint
	beq	el1_trap
	cmp	x1, #0x30		// Breakpoint
	beq	el1_trap
	cmp	x1, #0x3C		// BRK
	beq	el1_trap
	cmp	x1, #0x16		// HVC execution
	b.ne	4f			// ??
	b	2f			// Normal HVC

1:	load_all_regs
	add	sp, sp, #(8 * 36)
	eret

2:	mrs	x0, VTTBR_EL2		/* Host or guest hvc? */
	asr	x0, x0, #48
	cmp	x0, #HOST_VMID
	b.ne	guest_hvc_trap
	ldp	x0, x1, [sp, #(8 * 0)]	/* Definitely host */
	bl	hvccall
	b	1b

4:	mov	x0, #1
	mov	x1, sp
	b	dump_state
	b	1b

	invalid_vector	el2_sync_invalid
	invalid_vector	el2_irq_invalid
	invalid_vector	el2_fiq_invalid
	invalid_vector	el2_error_invalid
	invalid_vector	el1_sync_invalid
	invalid_vector	el1_irq_invalid
	invalid_vector	el1_fiq_invalid
	invalid_vector	el1_error_invalid

el2_sync:
	msr	SPSel, #1

	sub	sp, sp, #(8 * 32)
	save_all_regs
	/*
	 * Nothing to handle for time being, so just crash
	 */
	mov	x0, #2
	mov	x1, sp
	b	dump_state

smc_trap:
	mrs	x0, VTTBR_EL2		/* Host or guest smc? */
	asr	x0, x0, #48
	cmp	x0, #HOST_VMID
	b.ne	guest_smc_trap
	ldp	x0, x1, [sp, #(8 * 0)]	/* Definitely host */
	bl	smccall
	b	forward_aarch64sync

guest_smc_trap:
	mov	x0, #3
	mov	x1, sp
	b	dump_state
	b	1b

aarch64sync_eretback:
	nop				/* Do not remove this nop */
	restore_eret_info
	ldr	x30, [sp, #(8 * 30)]
	add	sp, sp, #(8 * 36)
	eret

forward_aarch64sync:
	save_eret_info
	adr x1, aarch64sync_eretback
	prepare_eretback x0, x1
	ldr	x0, [sp, #(8 * 0)]
	load_all_regs
	aarch64sync_forward

el1_trap:
	mrs	x0, VTTBR_EL2	/* Host or guest? */
	asr	x0, x0, #48
	cmp	x0, #HOST_VMID
	b.ne	2f
	cmp	x1, #0x24	/* Data abort?*/
	b.ne	1f
	/*
	 * If we arrive here from the process
	 * that owns the guest that's an
	 * indication we may need to make this
	 * address visible again to the host
	 * to enable the required data sharing
	 * between the host and guest.
	 */
	mrs	x1, TTBR0_EL1
	mrs	x2, FAR_EL2
	bl	map_back_host_page
	cmp	x0, #1
	b.ne	1f
	/*
	 * Now since it indeed was an
	 * abort from the owning process
	 * and we mapped back the needed
	 * memory let's get us back where
	 * we came from.
	 */
	load_all_regs
	ldr	x0, [sp, #(8 * 0)]
	add	sp, sp, #(8 * 36)
	eret
1:	b	forward_aarch64sync
2:	get_kern_exit	x3, x0
	get_vcpu_ptr	x1, x0
	mov	x0, #ARM_EXCEPTION_TRAP
	br	x3

fpsimd_trap:
	get_fpsimd_guest_restore	x3, x0
	cmp	x3, #0
	b.eq	el1_trap
	get_vcpu_ptr	x1, x0
	mov	x0, #0x7
	br	x3

el1_irq:
	msr     SPSel, #1

	save_clobber_regs
	get_kern_exit	x3, x0
	get_vcpu_ptr	x1, x0
	mov	x0, #ARM_EXCEPTION_IRQ
	br	x3

guest_hvc_trap:
	ldp	x0, x1, [sp, #(8 * 0)]
	bl	psci_reg
	load_all_regs
	get_kern_exit	x3, x0
	get_vcpu_ptr	x1, x0
	mov	x0, #ARM_EXCEPTION_TRAP
	br	x3

el1_error:
	msr     SPSel, #1

	save_clobber_regs
	get_kern_exit	x3, x0
	get_vcpu_ptr	x1, x0
	mov	x0, #ARM_EXCEPTION_EL1_SERROR
	br	x3
