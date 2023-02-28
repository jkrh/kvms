/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASSERT_H__
#define __ASSERT_H__

#ifndef assert
#define assert(expr)							\
	if (!(expr)) {							\
		__assert(__func__, __FILE__, __LINE__, #expr);		\
	}
#endif


#ifndef assert_nopanic
#define assert_nopanic(expr)						\
	if (!(expr)) {							\
		__assert_nopanic(__func__, __FILE__, __LINE__, #expr);	\
	}
#endif

#endif /* __ASSERT_H__ */
