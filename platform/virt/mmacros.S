.macro platform_aarch64sync
	str	x0, [sp, #-8]!
	mrs	x0, elr_el2
	add	x0, x0, #4
	msr	elr_el2, x0
	ldr	x0, [sp], #8
	eret
.endm
