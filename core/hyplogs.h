/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __HYPLOGS_H__
#define __HYPLOGS_H__

#include <stdint.h>
#include <stdio.h>

#define LOG_INFO 0
#define LOG_ERROR 1

#define LOG(...) __log(LOG_INFO, __func__, __VA_ARGS__)
#define ERROR(...) __log(LOG_ERROR, __func__, __VA_ARGS__)

#ifdef SYSREG_PRINT
#define PRINTREG(...) __log(LOG_INFO, __func__, __VA_ARGS__)
#else
#define PRINTREG(...)
#endif

#ifdef SPINNER
void spinner(void);
#else
static inline void spinner(void)
{

}
#endif // SPINNER

void log_init(void);
uint64_t read_log(void);
void __log(int level, const char *func, const char *fmt, ...);

#endif // __HYPLOGS__
