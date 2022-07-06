/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "kvms-test-common.h"
#include "kvms-test-asm.h"
#include "kvms-export.h"

MODULE_LICENSE("GPL");

uint64_t virt_to_ipa(uint64_t s1addr)
{

	uint64_t paddr;

	paddr = __s1e1r(s1addr);

	if ((paddr & 1) == 0) {
		paddr = (paddr & 0x0000FFFFFFFFF000);
		paddr |= (((uint64_t)s1addr) & (PAGE_SIZE - 1));
	} else
		paddr = ~0UL;

	return paddr;
}
