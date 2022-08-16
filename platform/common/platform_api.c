/* SPDX-License-Identifier: GPL-2.0-only */

/**
 * Default platform implementation. Override in platform specific code if there
 * is a need.
 */
#include "commondefines.h"
#include "hyplogs.h"
#include "platform_api.h"

WEAK_SYM
int platform_init_guest(uint32_t vmid)
{
	LOG("vmid %ld\n", vmid);

	return 0;
}

WEAK_SYM
int platform_allow_guest_smc(register_t cn, register_t a1, register_t a2,
			     register_t a3, register_t a4, register_t a5,
			     register_t a6, register_t a7)
{
	return 0;
}
