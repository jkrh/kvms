/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __NOSPEC_H__
#define __NOSPEC_H__

#ifndef OPTIMIZER_HIDE_VAR
/* Make the optimizer believe the variable can be manipulated arbitrarily. */
#define OPTIMIZER_HIDE_VAR(var)                                         \
	__asm__ ("" : "=r" (var) : "0" (var))
#endif

/* 64bit */
#ifndef BITS_PER_LONG
#define BITS_PER_LONG	64
#endif

/**
 * array_index_mask_nospec() - generate a ~0 mask when index < size, 0 otherwise
 * @index: array element index
 * @size: number of elements in array
 *
 * When @index is out of bounds (@index >= @size), the sign bit will be
 * set.  Extend the sign bit to all bits and invert, giving a result of
 * zero for an out of bounds index, or ~0 if within bounds [0, @size).
 */
#ifndef array_index_mask_nospec
static inline unsigned long array_index_mask_nospec(unsigned long index,
						    unsigned long size)
{
	/*
	 * Always calculate and emit the mask even if the compiler
	 * thinks the mask is not needed. The compiler does not take
	 * into account the value of @index under speculation.
	 */
	OPTIMIZER_HIDE_VAR(index);
	return ~(long)(index | (size - 1UL - index)) >> (BITS_PER_LONG - 1);
}
#endif

/*
 * array_index_nospec - sanitize an array index after a bounds check
 *
 * For a code sequence like:
 *
 *     if (index < size) {
 *         index = array_index_nospec(index, size);
 *         val = array[index];
 *     }
 *
 * ...if the CPU speculates past the bounds check then
 * array_index_nospec() will clamp the index within the range of [0,
 * size).
 */
#define array_index_nospec(index, size)					\
({									\
	__typeof__(index) _i = (index);					\
	__typeof__(size) _s = (size);					\
	unsigned long _mask = array_index_mask_nospec(_i, _s);		\
									\
	/*BUILD_BUG_ON(sizeof(_i) > sizeof(long));*/			\
	/*BUILD_BUG_ON(sizeof(_s) > sizeof(long));*/			\
									\
	(__typeof__(_i)) (_i & _mask);					\
})

#endif /* __NOSPEC_H__ */
