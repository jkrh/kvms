/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __STACKTRACE_H__
#define __STACKTRACE_H__

#define MAX_STACK_TRACE	16

struct stackframe {
	unsigned long fp;
	unsigned long pc;
};

struct stack_trace {
	unsigned int nr_entries, max_entries;
	unsigned long entries[MAX_STACK_TRACE];
	int skip;	/* input argument: How many entries to skip */
};

#define INIT_STACK_TRACE(name)				\
	struct stack_trace name = {			\
		.nr_entries = 0,			\
		.max_entries = MAX_STACK_TRACE,		\
		.entries = { 0 },			\
		.skip = 0				\
	};

#ifdef STACKTRACE
int unwind_frame(struct stackframe *frame);
void walk_stackframe(struct stackframe *frame,
		     int (*fn)(struct stackframe *, void *), void *data);
void dump_backtrace(int log_lvl, struct stackframe *sf, int spaces);
void __dump_stack(int log_lvl);

#define dump_stack()	__dump_stack(LOG_ERROR)

void save_stack_trace(struct stack_trace *trace);
void print_stack_trace(struct stack_trace *trace, int spaces);
int snprint_stack_trace(char *buf, size_t size,
			struct stack_trace *trace, int spaces);

#else /* !STACKTRACE */

static inline int unwind_frame(struct stackframe *frame) { return 0; }
static inline
void walk_stackframe(struct stackframe *frame,
		     int (*fn)(struct stackframe *, void *), void *data) { }
static inline
void dump_backtrace(int log_lvl, struct stackframe *sf, int spaces) { }
static inline void __dump_stack(int log_lvl) { }

#define dump_stack()

static inline void save_stack_trace(struct stack_trace *trace) { }
static inline void print_stack_trace(struct stack_trace *trace, int spaces) { }
static inline
int snprint_stack_trace(char *buf, size_t size,
			struct stack_trace *trace, int spaces) { return 0; }
#endif /* STACKTRACE */

#endif // __STACKTRACE_H__
