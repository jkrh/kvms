// SPDX-License-Identifier: GPL-2.0-only

#ifndef __KVMS_RS_H__
#define __KVMS_RS_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

int32_t gettimeofday(struct timeval *tv);

int32_t usleep(uint64_t usec);
#endif /* __KVMS_RS_H__ */
