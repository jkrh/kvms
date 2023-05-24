/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __KVM_GUESTCONFIG_H__
#define __KVM_GUESTCONFIG_H__

#include <stdint.h>
#include "commondefines.h"

typedef struct {
	char *guest_id;
	uint64_t hpa;
	uint64_t gpa;
	uint64_t len;
} guest_share_t;

WEAK_SYM
const guest_share_t guest_shares[] = {
	{ "guest0", 0x100000000UL, 0x100000000UL, 0x10000000UL },
	{ "guest1", 0x200000000UL, 0x100000000UL, 0x10000000UL },
	{ "guest2", 0x300000000UL, 0x100000000UL, 0x10000000UL },
	{ "guest3", 0x400000000UL, 0x100000000UL, 0x10000000UL },
	{ 0, 0, 0, 0 },
};

#endif // __KVM_GUESTCONFIG_H__
