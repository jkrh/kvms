#include "pt_regs.h"
#include "arm-sysregs.h"

#define SCTLR_EE_BIT		(1 << 25)

.macro set_little_endian
	mrs	x0, sctlr_el2
	bic	x0, x0, #SCTLR_EE_BIT
	msr	sctlr_el2, x0
	isb
.endm

.macro bss_mem_clear
	ldr	x0, =__BSS_START__
	ldr	x1, =__BSS_SIZE__
	bl	_zeromem16
.endm

.macro smp_processor_id reg tmp
	mrs	\reg, mpidr_el1
	mov	\tmp, \reg
	and	\reg, \reg, #MPIDR_AFF0_MASK
	ubfx	\tmp, \tmp, #6, #3
	add	\reg, \reg, \tmp
.endm

/*
 * Forward synchronous exception (lower EL using AArch64) to platform specific
 * implementation.
 */
.macro platform_aarch64sync
	sub	sp, sp, #(PT_REGS_STACK_ALLOC)
	stp	x0, x1, [sp, #(8 * 0)]
	save_all_regs

	mov	x0, #1
	mov	x1, sp
	bl	dump_state
.endm platform_aarch64sync
