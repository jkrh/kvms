.macro platform_aarch64sync
	mrs	x28, elr_el2
	add	x28, x28, #4
	msr	elr_el2, x28
	ret
.endm
