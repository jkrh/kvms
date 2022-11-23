#include "linuxmacros.h"
#include "host_defs.h"

.global	hyp_entrypoint

/*
 * hyp_entrypoint()
 * Cpu entry point for both warm and cold reset.
 */
hyp_entrypoint:
	mov	x27, x30
	smp_processor_id x0
	/* Stack setup */
	mov	x1, STACK_SIZE
	madd	x1, x1, x0, x1
	adr	x3, __stack
	add	x3, x3, x1

	msr	SPSel, #1
	mov sp, x3

	/*
	 * Assuming boot CPU #0
	 * TODO: Warm boot support.
	 */
	cmp x0, #0
	bne	1f

	/* Clear BSS */
	bss_mem_clear

1:	bl	main

.data
.global entrylock
.align	8
entrylock:
	.quad	0x000000000000
