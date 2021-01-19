/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __CDEFINES_H__
#define __CDEFINES_H__

#define PAGE_SIZE 0x1000UL
#define PAGE_SHIFT 12
#define PAGE_MASK 0xFFFFFFFFFFFFF000
#define UNUSED __attribute__((unused))
#define WEAK_SYM __attribute__((weak))
#define ALIGN(N) __attribute__((aligned(N)))
#define SECTION(N) __attribute__((section(N)))
#define DATA __attribute__((section(".data")))
#define NORETURN __attribute__ ((noreturn))
#define _WEAK_ALIAS(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((weak, alias (#name)));
#define WEAK_ALIAS(name, aliasname) _WEAK_ALIAS (name, aliasname)

#define SZ_1K 0x000000400UL
#define SZ_1M 0x000100000UL
#define SZ_1G 0x040000000UL
#define SZ_4G 0x100000000UL

#ifndef ROUND_UP
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#endif

#define string(x) #x

#endif
