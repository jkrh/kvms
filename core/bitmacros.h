/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __BITMACROS_H__
#define __BITMACROS_H__

#define bit_t(x) x
#define bit_to_mask(x) (0x1UL << ((x) & 63UL))
#define bit_set(c, flag) (bit_t(c) |= bit_to_mask(flag))
#define bit_drop(c, flag) (bit_t(c) &= ~bit_to_mask(flag))
#define bit_raised(c, flag) (bit_t(c) & bit_to_mask(flag))

static inline void set_bit_in_mem(int n, uint64_t *addr)
{
        addr[n / (sizeof(uint64_t) * 8)] |= 1UL << (n % (sizeof(uint64_t) * 8));
}

static inline void clear_bit_in_mem(int n, uint64_t *addr)
{
        addr[n / (sizeof(uint64_t) * 8)] &= ~(1UL << (n % (sizeof(uint64_t) * 8)));
}

static inline int get_bit_in_mem(int n, uint64_t *addr)
{
	return addr[n / (sizeof(uint64_t) * 8)] & ~(1UL << (n % (sizeof(uint64_t) * 8)));
}

#endif // __BITMACROS_H__
