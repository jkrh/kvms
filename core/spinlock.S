/* SPDX-License-Identifier: GPL-2.0-only */
.global spin_lock
.type spin_lock, %function
.align 2
spin_lock:
	sub	sp, sp, #(8 * 4)
	stp	x1, x2, [sp, #(8 * 2)]
	mrs	x1, mpidr_el1
1:	ldxr	x2, [x0]
	cbz	x2, 2f
	wfe
	b	1b
2:	stxr	w2, x1, [x0]
	cbz	w2, 3f
	b	1b
3:	dmb	sy
	ldp	x1, x2, [sp, #(8 * 2)]
	add	sp, sp, #(8 * 4)
	ret

.global spin_unlock
.type spin_unlock, %function
.align 2
spin_unlock:
	sub	sp, sp, #(8 * 4)
	str	x1, [sp, #(8 * 2)]
	mov	x1, 0
	str	x1, [x0]
	dmb	sy
	sev
	ldr	x1, [sp, #(8 * 2)]
	add	sp, sp, #(8 * 4)
	ret
