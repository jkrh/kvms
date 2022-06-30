#include <asm/alternative.h>
#include <asm/assembler.h>
#include <linux/linkage.h>

SYM_FUNC_START(__kvms_hvc_cmd)
	.global __kvms_hvc_cmd
	__kvms_hvc_cmd:
	hvc	#0
	ret

SYM_FUNC_START(__kvms_hvc_get)
	.global __kvms_hvc_get
	__kvms_hvc_get:
	hvc	#0
	ret

SYM_FUNC_START(__demo_pc_get)
	.global __demo_pc_get
	__demo_pc_get:
	adr x0, .
	ret

SYM_FUNC_START(__demo_s1e1r)
	.global __demo_s1e1r
	__demo_s1e1r:
	at	s1e1r, x0
	mrs	x0, PAR_EL1
	ret
