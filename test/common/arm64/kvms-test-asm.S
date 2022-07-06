/* SPDX-License-Identifier: GPL-2.0-only */
#include <asm/alternative.h>
#include <asm/assembler.h>
#include <linux/linkage.h>

SYM_FUNC_START(kvms_hyp_call)
	.global kvms_hyp_call
	kvms_hyp_call:
	hvc	#0
	ret

SYM_FUNC_START(kvms_hyp_get)
	.global kvms_hyp_get
	kvms_hyp_get:
	hvc	#0
	ret

SYM_FUNC_START(__pc_get)
	.global __pc_get
	__pc_get:
	adr x0, .
	ret

SYM_FUNC_START(__s1e1r)
	.global __s1e1r
	__s1e1r:
	at	s1e1r, x0
	mrs	x0, PAR_EL1
	ret