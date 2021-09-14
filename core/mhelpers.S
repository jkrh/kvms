/* SPDX-License-Identifier: GPL-2.0-only */

.globl _zeromem16

/* -----------------------------------------------------------------------
 * int _zeromem16(void *mem, unsigned int length);
 *
 * Initialise a memory region to 0.
 * The memory address must be 16-byte aligned.
 * Return zero in case of success, non-zero otherwise.
 * -----------------------------------------------------------------------
 */
.type _zeromem16, %function
_zeromem16:
	tst	x0, #0xf
	b.eq	z_operation
	b	z_nok
z_operation:
	add	x2, x0, x1
/* zero 16 bytes at a time */
z_loop16:
	sub	x3, x2, x0
	cmp	x3, #16
	b.lt	z_loop1
	stp	xzr, xzr, [x0], #16
	b	z_loop16
/* zero byte per byte */
z_loop1:
	cmp	x0, x2
	b.eq	z_ok
	strb	wzr, [x0], #1
	b	z_loop1
z_nok:
	mov	x0, #1
	b	z_end
z_ok:
	mov	x0, #0
z_end:
	ret
