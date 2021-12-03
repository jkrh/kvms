/* SPDX-License-Identifier: GPL-2.0-only */
#include "imath.h"

uint64_t pow(uint64_t x, uint64_t y)
{
	uint64_t tmp;

	if(!y)
		return 1;

	tmp = pow(x, (y / 2));
	if ((y % 2) == 0)
		return tmp * tmp;
	else
		return x * tmp * tmp;
}
