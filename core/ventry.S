/* SPDX-License-Identifier: GPL-2.0-only */
#include <mmacros.S>
#include <host_defs.h>

#include "pt_regs.h"
#include "linuxmacros.h"
#include "linuxdefines.h"
#include <psci.h>

	.global	guest_exit

.macro ventry target
	b	\target
	.balign 128
.endm

	.section .vectors
	.align 11

.macro invalid_vector label
\label:
	b	dumpcall
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

	sub	sp, sp, #(PT_REGS_STACK_ALLOC)
	stp	x0, x1, [sp, #(8 * 0)]

	/* Collect VMID to x0 */
	mrs	x0, VTTBR_EL2
	lsr	x0, x0, #48

	/* Exception class to x1 */
	mrs	x1, ESR_EL2
	ubfx	x1, x1, #26, #6

	cmp	x1, #0x24		// Data abort
	beq	handle_abort
	cmp	x1, #0x20		// Inst abort
	beq	handle_abort
	cmp	x1, #0x17		// SMC
	beq	smc_trap
	save_all_regs
	cmp	x1, #0x01		// WFI/WFE
	beq	el1_trap
	cmp	x1, #0x07		// SVE, SIMD, FP
	beq	fpsimd_trap
	cmp	x1, #0x18		// System instruction trap
	beq	memctrl_trap
	cmp	x1, #0x32		// Software step
	beq	el1_trap
	cmp	x1, #0x31		// Breakpoint
	beq	el1_trap
	cmp	x1, #0x30		// Breakpoint
	beq	el1_trap
	cmp	x1, #0x3C		// BRK
	beq	el1_trap
	cmp	x1, #0x16		// HVC execution
	b.ne	5f			// ??
	b	4f			// Normal HVC

3:	load_all_regs
	add	sp, sp, #(PT_REGS_STACK_ALLOC)
	eret

4:	cmp	x0, #GUEST_VMID_START
	bge	guest_hvc_trap
	ldp	x0, x1, [sp, #(8 * 0)]
	bl	hvccall
	b	3b

5:	mov	x0, #1
	mov	x1, sp
	b	dump_state

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

	sub	sp, sp, #(PT_REGS_STACK_ALLOC)
	stp	x0, x1, [sp, #(8 * 0)]
	save_all_regs

	/*
	 * Nothing to handle for time being, so just crash
	 */
	mov	x0, #2
	mov	x1, sp
	b	dump_state

memctrl_trap:
	#
	# Guest or host?
	#
	mrs	x0, VTTBR_EL2
	lsr	x0, x0, #48
	cmp	x0, #GUEST_VMID_START
	bge	el1_trap
	#
	# Host.
	#
	mov	x0, sp
	bl	memctrl_exec
	mrs	x0, ELR_EL2
	add	x0, x0, #4
	msr	ELR_EL2, x0
	load_all_regs
	ldp	x0, x1, [sp, #(8 * 0)]
	add	sp, sp, #(PT_REGS_STACK_ALLOC)
	eret

host_fastpath:
	cmp	x1, #0x24
	beq	host_data_abort
	cmp	x1, #0x20
	beq	host_instruction_abort
	cmp	x1, #0x17
	beq	host_smc_trap
	/* We should never get here */
	ldp	x0, x1, [sp, #(8 * 0)]
	b	dumpcall

wait_core_ready:
	/*
	 * Wait the hyp core to finish and give the aborting core
	 * another try to access the location. The faulting address
	 * might well be mapped already.
	 */
	str	x30, [sp, #(8 * 30)]
	mov	x0, x2
	bl	spin_lock
	/* Just wait for the hyp core and unlock once ready. */
	bl	spin_unlock
	ldp	x0, x1, [sp, #(8 * 0)]
	ldp	x2, x3, [sp, #(8 * 2)]
	ldr	x30, [sp, #(8 * 30)]
	add	sp, sp, #(PT_REGS_STACK_ALLOC)
	eret

handle_abort:
	stp	x2, x3, [sp, #(8 * 2)]
	/*
	 * If the lock is held this abort may be running at
	 * a core which is accessing the portion of memory
	 * for which the mapping is being currently altered.
	 */
	adr	x2, core_lock
	ldr	x3, [x2]
	cbnz	x3, wait_core_ready
	ldp	x2, x3, [sp, #(8 * 2)]

	cmp	x1, #0x24		// Data abort
	beq	data_abort
	cmp	x1, #0x20		// Inst abort
	beq	instruction_abort
	ldp	x0, x1, [sp, #(8 * 0)]
	b	dumpcall

data_abort:
	cmp	x0, #GUEST_VMID_START
	blt	_host_data_abort
	b	_guest_data_abort

_host_data_abort:
#ifdef HOSTBLINDING
	save_all_regs
	/*
	 * Host data abort
	 *
	 * If we arrive here from the process that "owns" the guest that's an
	 * indication we may have blinded a page used for data sharing between
	 * the host and the guest. Handle it by crashing the user process or the
	 * calling kernel or map the data back in depending on the config.
	 *
	 */
	mrs	x1, TTBR0_EL1
	mrs	x2, FAR_EL2
	mov	x3, sp
	bl	host_data_abort
	cmp	x0, #1
	b.ne	1f
	/*
	 * Now since it indeed was an abort from the owning process and we
	 * handled it, return.
	 */
	load_all_regs
	ldr	x0, [sp, #(8 * 0)]
	add	sp, sp, #(PT_REGS_STACK_ALLOC)
	eret
1:	load_all_regs
	b	forward_aarch64sync
#else
	b	host_fastforward
#endif

_guest_data_abort:
	save_all_regs
	b	el1_trap

instruction_abort:
	cmp	x0, #GUEST_VMID_START
	blt	host_instruction_abort
	b	guest_instruction_abort

host_instruction_abort:
	b	host_fastforward

guest_instruction_abort:
	save_all_regs
	b	el1_trap

smc_trap:
	cmp	x0, #GUEST_VMID_START
	blt	host_smc_trap
	b	guest_smc_trap

host_smc_trap:
	ldr	x0, [sp, #(8 * 0)]
	lsr	x0, x0, #24
	cmp	x0, #PSCI_SMC64
	b.ne	host_fastforward
	save_all_regs
	ldp	x0, x1, [sp, #(8 * 0)]
	bl	smccall
	load_all_regs
	b	forward_aarch64sync

guest_smc_trap:
	ldp	x0, x1, [sp, #(8 * 0)]
	save_all_regs
	bl	platform_allow_guest_smc
	cmp	x0, #0
	beq	1f
	mrs	x0, ELR_EL2
	add	x0, x0, #4
	msr	ELR_EL2, x0
	ldr	x0, [sp, #(8 * 0)]
	load_all_regs
	add	sp, sp, #(PT_REGS_STACK_ALLOC)
	smc	#0
	eret
1:	mov	x0, #3
	mov	x1, sp
	b	dump_state

host_fastforward:
	ldp	x0, x1, [sp, #(8 * 0)]
	b	forward_aarch64sync

/*
 * Forward synchronous exception (Lower EL using AArch64) to a platform
 * implementation in platform_aarch64sync
 */
forward_aarch64sync:
	ldp	x0, x1, [sp, #(8 * 0)]
	add	sp, sp, #(PT_REGS_STACK_ALLOC)
	platform_aarch64sync

el1_trap:
	cmp	x0, #GUEST_VMID_START
	bge	1f
	load_all_regs
	b	forward_aarch64sync
1:	mrs	x18, ESR_EL2
	mov	x19, #ARM_EXCEPTION_TRAP
	b	guest_exit

fpsimd_trap:
	cmp	x0, #GUEST_VMID_START
	bge	4f
	/* Not implemented */
	mov	x0, #4
	mov	x1, sp
	b	dump_state
4:	get_fpsimd_guest_restore	x3, x0
	cmp	x3, #0
	beq	5f
	get_vcpu_ptr	x1, x0
	mov	x0, #0x7
	br	x3
5:	mrs	x18, ESR_EL2
	mov	x19, #ARM_EXCEPTION_TRAP
	b	guest_exit

el1_irq:
	msr	SPSel, #1
	sub	sp, sp, #PT_REGS_STACK_ALLOC
	save_clobber_regs

	mrs	x0, VTTBR_EL2
	lsr	x0, x0, #48
	cmp	x0, #GUEST_VMID_START
	blt	dumpcall

	save_all_regs

	mov	x18, xzr
	mov	x19, #ARM_EXCEPTION_IRQ
	b	guest_exit

guest_hvc_trap:
	ldp	x0, x1, [sp, #(8 * 0)]
	bl	is_apicall
	cmp	x0, #0
	bne	6f
	ldp	x0, x1, [sp, #(8 * 0)]
	load_all_regs
	bl	psci_reg
	mrs	x18, ESR_EL2
	mov	x19, #ARM_EXCEPTION_TRAP
	b	guest_exit
6:	ldp	x0, x1, [sp, #(8 * 0)]
	load_all_regs
	bl	hvccall
	load_all_regs
	add	sp, sp, #(PT_REGS_STACK_ALLOC)
	eret

el1_error:
	msr	SPSel, #1
	sub	sp, sp, #(PT_REGS_STACK_ALLOC)
	stp	x0, x1, [sp, #(8 * 0)]
	save_all_regs

	mrs	x0, VTTBR_EL2
	lsr	x0, x0, #48
	cmp	x0, #GUEST_VMID_START
	blt	dumpcall

	mov	x18, xzr
	mov	x19, #ARM_EXCEPTION_EL1_SERROR
	b	guest_exit

dumpcall:
	msr	SPSel, #1
	sub	sp, sp, #(PT_REGS_STACK_ALLOC)
	stp	x0, x1, [sp, #(8 * 0)]
	save_all_regs

	mov	x0, #5
	mov	x1, sp
	b	dump_state

.data
.global core_lock
.align	8
core_lock:
	.quad	0x000000000000
