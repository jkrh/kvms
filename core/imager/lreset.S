#
# Input
# ------
# MMU = off, D-cache = off, I-cache = on or off
# CPU in EL2
# x26 = LR to restore on exit
# x28 = Address where the FDT is loaded
# x30 = Return address in EL1
#

#ifndef KERNEL_ADDR
#define KERNEL_ADDR 0x40200000
#endif

#ifndef HYP_START_ADDR
#define HYP_START_ADDR KERNEL_ADDR
#endif

#ifndef HYP_EXTRACT_ADDR
#define HYP_EXTRACT_ADDR 0xC0000000
#endif

/*
 * Macro borrowed from ARM Trusted Firmware, thanks.
 */
.macro _mov_imm16 _reg, _val, _shift
	.if (\_val >> \_shift) & 0xffff
		.if (\_val & (1 << \_shift - 1))
			movk	\_reg, (\_val >> \_shift) & 0xffff, LSL \_shift
		.else
			mov	\_reg, \_val & (0xffff << \_shift)
		.endif
	.endif
.endm

.macro mov_imm _reg, _val
	.if (\_val) == 0
			mov	 \_reg, #0
	.else
			_mov_imm16	\_reg, (\_val), 0
			_mov_imm16	\_reg, (\_val), 16
			_mov_imm16	\_reg, (\_val), 32
			_mov_imm16	\_reg, (\_val), 48
	.endif
.endm

.macro save_all_regs
	stp	x0, x1, [sp, #(8 * 0)]
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

.global _start
_start:
	adr	x25, __stack
	mov	sp, x25
	add	sp, sp, #4096
	sub	sp, sp, #256
	save_all_regs

	mov_imm	x0, HYP_START_ADDR
	mov_imm	x1, HYP_EXTRACT_ADDR
	mov	x2, sp
	bl	main
