/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __GIC_H__
#define __GIC_H__

#include "stdint.h"
#include "host_platform.h"
#include "commondefines.h"
#include "gicd-regs.h"
#include "helpers.h"

#define gdreg_addr(reg) ((volatile uint32_t *)(GIC_DIST_ADDR + (reg)))
#define read_gicdreg(reg) (*(gdreg_addr(reg)))
#define write_gicdreg(reg, val) (*gdreg_addr(reg) = val)

uint32_t print_gicd_reg(uint32_t reg);

#endif // __GIC_H__
