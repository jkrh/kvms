/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVMS_TEST_COMMON_H__
#define __KVMS_TEST_COMMON_H__

#ifndef __ASSEMBLY__
extern uint64_t virt_to_ipa(uint64_t vaddr);
extern int kvms_hyp_call(unsigned long cmd, ...);
extern uint64_t kvms_hyp_get(unsigned long cmd, ...);
#endif // __ASSEMBLY__

#endif // __KVMS_TEST_COMMON_H__
