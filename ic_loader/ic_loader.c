/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdint.h>
#include <string.h>

#include "kic_defs.h"
#include "hvccall-defines.h"
#include "psci.h"
#include "commondefines.h"

#define PAGE 0x1000

__attribute__((__section__(".stack"))) uint32_t stack[512];

int call_hyp(uint64_t fid, uint64_t x1)
{
	register uint64_t ret;

	__asm__ __inline__ __volatile__ (
		"mov x0, %[x0]\n\t"
		"mov x1, %[x1]\n\t"
		"hvc	#0\n"
		"mov %[ret], x0\n\t"
		: [ret] "=r"(ret)
		: [x0] "r" (fid), [x1] "r"(x1)
		: "x0", "x1", "memory");

	return ret;
}

void err_handler(int ret)
{
#ifdef DEBUG
	if (ret == KIC_FATAL) {
		call_hyp(PSCI_SYSTEM_OFF, 0);
		while(1);
	}
#else
	call_hyp(PSCI_SYSTEM_OFF, 0);
	while(1);
#endif
}

void ic_loader(uint64_t sp[], uint64_t start)
{
	volatile uint64_t dummy;
	uint8_t *p;
	gad_t *sign_params = (gad_t *) start;
	uint64_t image_size = sign_params->image_size;
	uint64_t dtb = sign_params->dtb;
	uint64_t dtb_size = sign_params->dtb_size;;
	int ret;

	ret = call_hyp(HYP_GUEST_INIT_IMAGE_CHECK, start);
	if (ret) {
		err_handler(ret);
		return;
	}

	/* S2 map kernel image */
	p = (uint8_t *) sign_params;
	while ((uint64_t) p < start + image_size) {
		dummy += *p;
		p += PAGE;
	}

	/* restore original first page */
	memcpy((void *) start, p, PAGE);

	/* If dtb check is in use */
	if (dtb) {
		/* x0 should point to dtb */
		sp[0] = dtb;
	}

	/* copy  dtb to its location  */
	if (dtb && dtb_size) {
		memcpy((void *)dtb, p + PAGE,
		       ROUND_UP(dtb_size, sizeof(uint64_t)));
	}

	ret = call_hyp(HYP_GUEST_DO_IMAGE_CHECK, (uint64_t) start);
	if (ret)
		err_handler(ret);
}
