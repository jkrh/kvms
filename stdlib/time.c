#include <sys/time.h>
#include <string.h>
#include <stdint.h>
#include "helpers.h"

#define SECONDS      1
#define MILLISECONDS 1000
#define MICROSECONDS 1000000
#define NANOSECONDS  1000000000

int gettimeofday(struct timeval *tv, void *tz)
{
	uint64_t cntptval_org;
	uint64_t cntfrq_org;
	uint64_t val;

	memset(tv, 0, sizeof(*tv));
	cntfrq_org = read_reg(CNTFRQ_EL0);
	cntptval_org = read_reg(CNTPCT_EL0);

	val = cntptval_org * MICROSECONDS;
	val = val / cntfrq_org;
	tv->tv_usec = val;

	val = cntptval_org * SECONDS;
	val = val / cntfrq_org;
	tv->tv_sec = val;

	return 0;
}
