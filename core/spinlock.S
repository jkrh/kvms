/* SPDX-License-Identifier: GPL-2.0-only */
.global spin_lock
.type spin_lock, %function
spin_lock:
	sub	sp, sp, #(8 * 4)
	str	x1, [sp, #(8 * 2)]
	str	x2, [sp, #(8 * 3)]
1:	ldxr	x2, [x0]
	cbz	x2, 2f
	wfe
	b	1b
2:	mov	x1, 1
	stxr	w2, x1, [x0]
	cbz	w2, 3f
	b	1b
3:	dmb	sy
	ldr	x1, [sp, #(8 * 2)]
	ldr	x2, [sp, #(8 * 3)]
	add	sp, sp, #(8 * 4)
	ret

.global spin_unlock
.type spin_unlock, %function
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
