#
# Input
# ------
# MMU = off, D-cache = off, I-cache = on or off
# CPU in EL2
# x26 = LR to restore on exit
# x28 = Address where the FDT is loaded
# x30 = Return address in EL1
#
#include "host_defs.h"

.global _start
_start:
	adr	x25, __stack
	add	x25, x25, STACK_SIZE
	mov	sp, x25
	mov	x27, x30

	adr	x0, entrylock
	bl	spin_lock
	bl	main

.data
.global entrylock
.align	8
entrylock:
	.quad	0x000000000000

.data
.global __guest_exit
__guest_exit:
	.quad   0x000000000000
