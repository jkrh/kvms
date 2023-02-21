/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KALLSYMS_H__
#define __KALLSYMS_H__

#include "sections.h"

#define KSYM_NAME_LEN 192

static inline int is_kernel_text(unsigned long addr)
{
	if ((addr >= (unsigned long)_stext && addr <= (unsigned long)_etext))
		return 1;
	return 0;
}

static inline int is_kernel(unsigned long addr)
{
	if (addr >= (unsigned long)_stext && addr <= (unsigned long)_end)
		return 1;
	return 0;
}

static inline int is_ksym_addr(unsigned long addr)
{
#ifdef KALLSYMS_ALL
	return is_kernel(addr);
#else
	return is_kernel_text(addr);
#endif
}

unsigned long kallsyms_lookup_name(const char *name);
int kallsyms_on_each_symbol(int (*fn)(void *, const char *, unsigned long),
			    void *data);
int kallsyms_lookup_size_offset(unsigned long addr, unsigned long *symbolsize,
				unsigned long *offset);
const char *kallsyms_lookup(unsigned long addr,
			    unsigned long *symbolsize,
			    unsigned long *offset,
			    char *namebuf);
int lookup_symbol_name(unsigned long addr, char *symname);
int lookup_symbol_attrs(unsigned long addr, unsigned long *size,
			unsigned long *offset, char *name);
int sprint_symbol(char *buffer, unsigned long address);
int sprint_symbol_no_offset(char *buffer, unsigned long address);
int sprint_backtrace(char *buffer, unsigned long address);

#endif // __KALLSYMS_H__