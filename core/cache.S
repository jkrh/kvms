/* SPDX-License-Identifier: GPL-2.0-only */
.macro	dcache_line_size  reg, tmp
	mrs	\tmp, ctr_el0
	ubfx	\tmp, \tmp, #16, #4
	mov	\reg, #4
	lsl	\reg, \reg, \tmp
.endm

.global __inval_dcache_area
.type __inval_dcache_area, %function
__inval_dcache_area:
/*
 *	- start   - virtual start address of region
 *	- size    - size in question
*/
	add	x1, x1, x0
	dcache_line_size x2, x3
	sub	x3, x2, #1
	tst	x1, x3				// end cache line aligned?
	bic	x1, x1, x3
	b.eq	1f
	dc	civac, x1			// clean & invalidate D / U line
1:	tst	x0, x3				// start cache line aligned?
	bic	x0, x0, x3
	b.eq	2f
	dc	civac, x0			// clean & invalidate D / U line
	b	3f
2:	dc	ivac, x0			// invalidate D / U line
3:	add	x0, x0, x2
	cmp	x0, x1
	b.lo	2b
	dsb	sy
	ret

.global __flush_dcache_area
.type __flush_dcache_area, %function
__flush_dcache_area:
	dcache_line_size x2, x3
	add	x1, x0, x1
	sub	x3, x2, #1
	bic	x0, x0, x3
1:	dc	civac, x0			// clean & invalidate D line
	add	x0, x0, x2
	cmp	x0, x1
	b.lo	1b
	dsb	sy
	ret

.global __flush_icache_area
.type __flush_icache_area, %function
__flush_icache_area:
	sub     sp, sp, #(8 * 4)
	stp	x0, x1, [sp, #(8 * 0)]
	stp	x2, x4, [sp, #(8 * 2)]
	add	x1, x1, x0			// x0: base address, x1: length
	mrs	x2, ctr_el0

	and	x2, x2, #0xF
	mov	x3, #4
	lsl	x3, x3, x2			// x3: the cache line
	sub	x4, x3, 0x1
	bic	x4, x0, x4			// x4: aligned base address

ival:	ic	ivau, x4			// invalidate i-line PoU
	add	x4, x4, x3
	cmp	x4, x1
	b.lt	ival
	dsb	ish
	isb
	ldp	x0, x1, [sp, #(8 * 0)]
	ldp	x1, x2, [sp, #(8 * 2)]
	add	sp, sp, #(8 * 4)
	ret
