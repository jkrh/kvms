/* SPDX-License-Identifier: GPL-2.0-only */

#include "host_platform.h"
#include "hyplogs.h"
#include "gicd-regs.h"
#include "gic.h"

#define GICD_REG(x) { .reg = GICD_##x, .name = "GICD_"#x, }

static const struct {
	uint32_t reg;
	const char *name;
} gicd_regs[] = {
	GICD_REG(CTLR),
	GICD_REG(TYPER),
	GICD_REG(IIDR),
	GICD_REG(TYPER2),
	GICD_REG(STATUSR),
	GICD_REG(IDREGS),
};

USED
uint32_t print_gicdreg(uint32_t reg)
{
	unsigned int i;
	uint32_t r = 0;
	const char *name = NULL;

	r = read_gicdreg(reg);

	for (i = 0; i < sizeof(gicd_regs) / sizeof(gicd_regs[0]); i++)
		if (gicd_regs[i].reg == reg) {
			name = gicd_regs[i].name;
			break;
		}

	if (name)
		LOG("%s: 0x%x\n", name, r);
	else
		LOG("0x%x: 0x%x\n", reg, r);

	return r;
}
