// SPDX-License-Identifier: GPL-2.0-only

#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include "hyplogs.h"
#include "commondefines.h"

#define BUFSIZE 128

extern int __getchar(void);

static struct timeval boot_ts ALIGN(16);

#ifdef SPINNER
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

void log_init()
{
	gettimeofday(&boot_ts, NULL);
}

static int __printbuf(char *buf)
{
	int count = 0;

	buf[BUFSIZE - 1] = '\0';
	while (buf[count]) {
		if (putchar(buf[count]) != EOF) {
			count++;
		} else {
			count = EOF;
			break;
		}
	}

	return count;
}

void __log(int level, const char *func, const char *fmt, ...)
{
	char buf[BUFSIZE];
	struct timeval tv2;
	register uint64_t ts;
	va_list args;

	gettimeofday(&tv2, NULL);
	ts = (tv2.tv_usec - boot_ts.tv_usec) / 1000;

	if (level)
		printf("\033[0;31m");

	printf("[%*.*lu] %*.*s ", 12, 12, ts, 16, 16, func);
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	va_end(args);

	__printbuf(buf);
	putchar('\r');

	if (level)
		printf("\033[0m");
}
