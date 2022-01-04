/* SPDX-License-Identifier: GPL-2.0-only */

#include "host_platform.h"
#include "hyplogs.h"
#include "gicd-regs.h"
#include "gic.h"

USED
uint32_t print_gicdreg(uint32_t reg)
{
	uint32_t r = 0;

	r = read_gicdreg(reg);

	switch (reg) {
	case GICD_CTLR:
		LOG("GICD_CTLR: %x\n", r);
		break;
	case GICD_TYPER:
		LOG("GGIC_TYPER: 0x%x\n", r);
		break;
	case GICD_IIDR:
		LOG("GICD_IIDR: 0x%x\n", r);
		break;
	case GICD_TYPER2:
		LOG("GICD_TYPER2: 0x%x\n", r);
		break;
	case GICD_STATUSR:
		LOG("GICD_STATUSR: 0x%x\n", r);
		break;
	case GICD_IDREGS:
		LOG("GICD_IDREGS: 0x%x\n", r);
		break;
	default:
		LOG("??: 0x%x\n", r);
		break;
	}

	return r;
}
