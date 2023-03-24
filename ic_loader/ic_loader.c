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
uint64_t laddr[KIC_IMAGE_COUNT];

void ic_loader(uint64_t sp[], uint64_t start)
{
	volatile uint64_t dummy;

	uint8_t *p;

	kic_image_t *img;

	gad_t *gad = (gad_t *) start;
	int ret;
	int i;

	/* map the first page */
	p = (uint8_t *) start;
	dummy += *p;

	ret = call_hyp(HYP_GUEST_INIT_IMAGE_CHECK, start);
	if (ret) {
		err_handler(ret);
		return;
	}
	for (i = 0 ; i < KIC_IMAGE_COUNT; i++) {
		img = &gad->images[i];
		if (img->macig) {
			if (img->flags & KIC_FLAG_LOAD) {
				laddr[i] = img->load_address;
				if (laddr[i] == 0) {
					/* X0 contains the load address*/
					laddr[i] = sp[0];
				}
				if (img->flags & KIC_FLAG_STORE_ADDR_TO_X0) {
					/* */
					sp[0] = laddr[i];
				}

				memcpy((void *)laddr[i], (void *) start + img->offset,
					ROUND_UP(img->size, sizeof(uint64_t)));
			} else {
				laddr[i] = start;
				p = (uint8_t *) start;
				while ((uint64_t) p < start + img->size) {
					dummy += *p;
					p += PAGE;
				}
			}
		}
	}

	/* restore original first page */
	memcpy((void *) start, (void *) start + gad->images[0].size, PAGE);

	ret = call_hyp(HYP_GUEST_DO_IMAGE_CHECK, (uint64_t) laddr);
	if (ret)
		err_handler(ret);
}
