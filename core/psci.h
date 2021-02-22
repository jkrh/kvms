/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __PSCI_H__
#define __PSCI_H__

#include <stdint.h>
#include "helpers.h"

#define PSCI_VERSION		0x84000000UL
#define PSCI_CPU_SUSPEND_SMC64	0xC4000001UL
#define PSCI_CPU_OFF		0x84000002UL
#define PSCI_CPU_ON_SMC64	0xC4000003UL
#define PSCI_AFFINITY_INFO	0xC4000004UL
#define PSCI_MIGRATE		0xC4000005UL
#define PSCI_MIGRATE_INFO_TYPE	0x84000006UL
#define PSCI_SYSTEM_OFF		0x84000008UL
#define PSCI_SYSTEM_RESET	0x84000009UL

#define PSCI_SUCCESS		0
#define PSCI_NOT_SUPPORTED	-1
#define PSCI_INVALID_PARAMETERS	-2
#define PSCI_DENIED		-3
#define PSCI_ALREADY_ON		-4
#define PSCI_ON_PENDING		-5
#define PSCI_INTERNAL_FAILURE	-6
#define PSCI_NOT_PRESENT	-7
#define PSCI_DISABLED		-8
#define PSCI_INVALID_ADDRESS	-9

void psci_reg(u_register_t cn, u_register_t a1, u_register_t a2, u_register_t a3,
	      u_register_t a4, u_register_t a5);

#endif // __PSCI_H__
