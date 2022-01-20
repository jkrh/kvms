/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __PT_REGS_H__
#define __PT_REGS_H__

#ifndef __ASSEMBLY__
#include <stdint.h>

/*
 * User structures for general purpose, floating point and debug registers.
 */
struct user_pt_regs {
	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
};

/*
 * This struct defines the way the registers are stored on the stack during an
 * exception. Note that sizeof(struct pt_regs) has to be a multiple of 16 (for
 * stack alignment). struct user_pt_regs must form a prefix of struct pt_regs.
 */
struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			uint64_t regs[31];
			uint64_t sp;
			uint64_t pc;
			uint64_t pstate;
		};
	};
};
#endif // __ASSEMBLY__

#define PT_REGS_SIZE (8 * 36)

#endif /* !__PT_REGS_H__ */
