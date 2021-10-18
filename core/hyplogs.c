// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include "hyplogs.h"

extern int __getchar(void);

#ifdef DEBUG
const char bars[] = { '/', '-', '\\', '|' };
const int nb = sizeof(bars) / sizeof(char);

void spinner(void)
{
	static int pos;

	printf("%c\r", bars[pos]);
	pos = (pos + 1) % nb;
}
#endif

uint64_t read_log(void)
{
	int n = 0;
	uint64_t res = 0;

#ifndef DEBUG
	int chr;

	while (n < 7 && (chr = __getchar()) != -1) {
		res = (res << 8) | chr;
		n++;
	}
	res = (res << 8) | n;
#endif
	if (n == 0)
		return -ENODATA;

	return res;
}
