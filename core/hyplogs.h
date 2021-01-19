/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __HYPLOGS_H__
#define __HYPLOGS_H__

#include <stdint.h>
#include <stdio.h>

#define LOG(...)  \
do { \
	printf("[------------] " __VA_ARGS__); (void)putchar('\r'); \
} while(0);

#define ERROR(...) \
do { \
	printf("[!!!!!!!!!!!!] " __VA_ARGS__); (void)putchar('\r'); \
} while(0);

#ifdef DEBUG
void spinner(void);
#else
static inline void spinner(void)
{

}
#endif // DEBUG

uint64_t read_log(void);

#endif // __HYPLOGS__
