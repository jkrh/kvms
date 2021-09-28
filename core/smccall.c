// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <spinlock.h>

#include "armtrans.h"
#include "bits.h"
#include "helpers.h"
#include "host_platform.h"
#include "hyplogs.h"
#include "smccall.h"

unsigned int smccall(register_t cn, register_t a1, register_t a2, register_t a3,
		     register_t a4, register_t a5, register_t a6, register_t a7,
		     register_t a8, register_t a9)
{
	uint64_t cmd = cn;

	switch (cmd) {
	case PSCI_CPU_SUSPEND_SMC64:
	case PSCI_CPU_ON_SMC64:
		psci_reg(cn, a1, a2, a3, a4, a5);
		break;
	case 0xFFFFFFFE:
		LOG("Identity query...\n");
		return 0x99;
	default:
		break;
	}

	return cmd;
}
