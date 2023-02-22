/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __STACKTRACE_H__
#define __STACKTRACE_H__

struct stackframe {
	unsigned long fp;
	unsigned long pc;
};

#ifdef STACKTRACE
int unwind_frame(struct stackframe *frame);
void walk_stackframe(struct stackframe *frame,
		     int (*fn)(struct stackframe *, void *), void *data);
void dump_backtrace(int log_lvl, struct stackframe *sf);
void __dump_stack(int log_lvl);

#define dump_stack()	__dump_stack(LOG_ERROR)

#else /* !STACKTRACE */

int unwind_frame(struct stackframe *frame) { return 0; }
void walk_stackframe(struct stackframe *frame,
		     int (*fn)(struct stackframe *, void *), void *data) { }
void dump_backtrace(int log_lvl, struct stackframe *sf) { }
void __dump_stack(int log_lvl) { }

#define dump_stack()
#endif

#endif // __STACKTRACE_H__
