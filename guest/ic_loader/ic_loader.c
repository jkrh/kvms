/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdint.h>
#include "hvccall-defines.h"
#include "kic.h"

__attribute__((__section__(".padding"))) uint64_t pad = 0x12345678;
/* padding section ensures that objcopy does not generate extra bytes
 * to end of binary
 */

__attribute__((__section__(".signature"))) sign_params_t params;
 /*  Placeholder for load parameters and signature. These are copied
  * to end of binary
  */

__attribute__((__section__(".stack"))) uint32_t stack[256];

__attribute__((always_inline))
/* call_hyp must be inlined. Hypervisor checks that hcv is made from ic_loader.
*/
inline int call_hyp(uint64_t fid, uint64_t x1, uint64_t x2,
		    uint64_t x3, uint64_t x4)
{
	register uint64_t ret;

	__asm__ __inline__ __volatile__ (
		"mov x0, %[x0]\n\t"
		"mov x1, %[x1]\n\t"
		"mov x2, %[x2]\n\t"
		"mov x3, %[x3]\n\t"
		"mov x4, %[x4]\n\t"
		"hvc	#0\n"
		"mov %[ret], x0\n\t"
		: [ret] "=r"(ret)
		: [x0] "r" (fid), [x1] "r"(x1), [x2] "r"(x2),
		  [x3] "r"(x3), [x4] "r"(x4)
		: "x0", "x1", "x2", "x3", "x4", "memory");

	return ret;
}



/* global dummy variable ensures that compiler optimizer does not
 *  remove while loop */
uint32_t dummy;

int ic_loader(uint64_t kernel_addr)
{
	uint64_t check_area_end;
	int32_t ret;

	check_area_end = (uint64_t) &params.signature;

	call_hyp(HYP_GUEST_INIT_IMAGE_CHECK,
		 kernel_addr, check_area_end, 0, 0);

	while (kernel_addr < check_area_end) {
		dummy += *(uint32_t *) kernel_addr;
		kernel_addr += 4096;
	}

	ret = call_hyp(HYP_GUEST_DO_IMAGE_CHECK, (uint64_t) &params, 0, 0, 0);
	return ret;
}
