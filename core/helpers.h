/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __HELPERS_H__
#define __HELPERS_H__

#include <stdint.h>
#include <stdio.h>

#include "hyplogs.h"
#include "commondefines.h"
#include "host_platform.h"
#include "host_defs.h"
#include "armtrans.h"
#include "imath.h"

#define PAR_EL1_PAMASK 0x0000FFFFFFFFF000

#define read_reg(r)                                                            \
	__extension__({                                                        \
		uint64_t value;                                                \
		__asm__ __volatile__("mrs	%0, " string(r)                \
				     : "=r"(value));                           \
		value;                                                         \
	})

#define read_gpreg(r)                                                          \
	__extension__({                                                        \
		uint64_t value;                                                \
		__asm__ __volatile__("mov	%0, " string(r)                \
				     : "=r"(value));                           \
		value;                                                         \
	})

#define write_reg(r, v)                                                        \
	do {                                                                   \
		uint64_t value = (uint64_t)v;                                  \
		__asm__ __volatile__("msr	" string(r) ", %0"             \
				     :                                         \
				     : "r"(value));                            \
	} while (0);

/* Resolve el1 stage 1 va */
#define ats1e1r(va)                                                            \
	({                                                                     \
		uint64_t value;                                                \
		__asm__ __volatile__("at	s1e1r, %[vaddr]\n"             \
				     "mrs	%[paddr], PAR_EL1\n"           \
				     : [paddr] "=r"(value)                     \
				     : [vaddr] "r"(va)                         \
				     :);                                       \
		value;                                                         \
	})

static inline void *at_s1e1r(void *s1addr)
{

	uint64_t ipa;

	ipa = ats1e1r(s1addr);

	if ((ipa & 1) == 0) {
		ipa = (ipa & PAR_EL1_PAMASK);
		ipa |= (((uint64_t)s1addr) & (PAGE_SIZE - 1));
	} else
		ipa = ~0UL;

	return (void *)ipa;
}

static inline void *virt_to_ipa(void *s1addr)
{
	return at_s1e1r(s1addr);
}

/* Perform stage 1 and stage 2 address translation */
#define s12e1r(va)                                                             \
	({                                                                     \
		uint64_t value;                                                \
		__asm__ __volatile__("at	s12e1r, %[vaddr]\n"            \
				     "mrs	%[paddr], PAR_EL1\n"           \
				     : [paddr] "=r"(value)                     \
				     : [vaddr] "r"(va)                         \
				     :);                                       \
		value;                                                         \
	})

/**
 * Use 'at s12e1r' to resolve physical address from a stage1 address.
 *
 * The target must be in correct context i.e. stage 1 translation
 * tables (pointed by TTBR0_EL1 and TTBR1_EL1) and stage 2
 * VTTBR_EL2 must correspond the context for which the address
 * is being resolved for.
 *
 * @param s1addr the stage 1 address
 * @return the physical address on success or ~0UL on failure
 */
static inline void *at_s12e1r(void *s1addr)
{

	uint64_t paddr;

	paddr = s12e1r(s1addr);

	if ((paddr & 1) == 0) {
		paddr = (paddr & PAR_EL1_PAMASK);
		paddr |= (((uint64_t)s1addr) & (PAGE_SIZE - 1));
	} else
		paddr = ~0UL;

	return (void *)paddr;
}

static inline uint64_t el1_fill(void)
{
	uint64_t t1sz, fill;

	t1sz = TCR_EL1_T1SZ(read_reg(TCR_EL1));
	fill = ~0 - pow(2,(64 - t1sz)) + 1;

	return fill;
}

static inline void *virt_to_phys(void *s1addr)
{
	return at_s12e1r(s1addr);
}

/* Resolve el2 stage 1 va */
#define ats1e2r(va)                                                            \
	({                                                                     \
		uint64_t value;                                                \
		__asm__ __volatile__("at	s1e2r, %[vaddr]\n"             \
				     "mrs	%[paddr], PAR_EL1\n"           \
				     : [paddr] "=r"(value)                     \
				     : [vaddr] "r"(va)                         \
				     :);                                       \
		value;                                                         \
	})

/*
 * x20 recycle is a product of working around a gcc optimizer bug,
 * apogies.
 */

#define tlbi_el1_va(va)                                                        \
	do {                                                                   \
		__asm__ __volatile__("mov	x20, %[vaddr]\n"               \
				     "lsr	%[vaddr], %[vaddr], #12\n"     \
				     "tlbi	vae1is, %[vaddr]\n"            \
				     "mov	%[vaddr], x20\n"               \
				     :                                         \
				     : [vaddr] "r"(va)                         \
				     : "memory", "x20");                       \
	} while (0);

#define tlbi_el1_ipa(va)                                                       \
	do {                                                                   \
		__asm__ __volatile__("mov	x20, %[vaddr]\n"               \
				     "lsr	%[vaddr], %[vaddr], #12\n"     \
				     "tlbi	ipas2e1is, %[vaddr]\n"        \
				     "mov	%[vaddr], x20\n"               \
				     :                                         \
				     : [vaddr] "r"(va)                         \
				     : "memory", "x20");                       \
	} while (0);

#define tlbi_el2_va(va)                                                        \
	do {                                                                   \
		__asm__ __volatile__("mov	x20, %[vaddr]\n"               \
				     "lsr	%[vaddr], %[vaddr], #12\n"     \
				     "tlbi	vae2is, %[vaddr]\n"            \
				     "mov	%[vaddr], x20\n"               \
				     :                                         \
				     : [vaddr] "r"(va)                         \
				     : "memory", "x20");                       \
	} while (0);

static inline uint64_t ioread64(const volatile void *addr)
{
	uint64_t val;

	__asm__ __volatile__("ldr	%x0, [%0]\n"
			     "dmb	sy\n"
			     : "=r" (val)
			     : "r" (addr));
	return val;
}

static inline uint32_t ioread32(const volatile void *addr)
{
	uint32_t val;

	__asm__ __volatile__("ldr	%w0, [%0]\n"
			     "dmb	sy\n"
			     : "=r" (val)
			     : "r" (addr));
	return val;
}

static inline void iowrite64(uint64_t val, volatile void *addr)
{

	__asm__ __volatile__("dmb	sy\n"
			     "str	%x0, [%1]\n"
			     : : "r" (val), "r" (addr));
}

static inline void iowrite32(uint32_t val, volatile void *addr)
{

	__asm__ __volatile__("dmb	sy\n"
			     "str	%w0, [%1]\n"
			     : : "r" (val), "r" (addr));
}

#define get_current_vmid() (read_reg(VTTBR_EL2) >> 48)
#define set_current_vmid(x) write_reg(VTTBR_EL2, (read_reg(VTTBR_EL2) | ((uint64_t)x << 48)))

static inline uint64_t smp_processor_id()
{
	uint64_t value;

	value = read_reg(mpidr_el1);
	value &= PLAT_CPU_AFF_MASK;
	value = value >> PLAT_CPU_AFF_SHIFT;

	return value;
}

static inline void hexdump(const char *token, uint8_t *data, int len)
{
	printf("%s: ", token);
	for (int i=0; i < len; i++) {
		printf("%02hhx:", data[i]);
        }
	printf("\n");
}

#define tlbialle1() __asm__ __volatile__("tlbi	alle1\n" : : : "memory");

#define tlbialle1is() __asm__ __volatile__("tlbi	alle1is\n" : : : "memory");

#define tlbivmalle1is() __asm__ __volatile__("tlbi	vmalle1is\n" : : : "memory");

#define tlbialle2() __asm__ __volatile__("tlbi	alle2\n" : : : "memory");

#define tlbialle2is() __asm__ __volatile__("tlbi	alle2is\n" : : : "memory");

#define tlbivmall() __asm__ __volatile__("tlbi	vmalls12e1\n" : : : "memory");

#define tlbivmalls12e1is() __asm__ __volatile__("tlbi	vmalls12e1is\n" : : : "memory");

#define dmb() __asm__ __volatile__("dmb	sy\n" : : : "memory");

#define dsb() __asm__ __volatile__("dsb	sy\n" : : : "memory");

#define dsbishst() __asm__ __volatile__("dsb	ishst\n" : : : "memory");

#define dsbish() __asm__ __volatile__("dsb	ish\n" : : : "memory");

#define isb() __asm__ __volatile__("isb	sy\n" : : : "memory");

#define smc() __asm__ __volatile__("smc	#0\n" : : :);

#define eret() __asm__ __volatile__("eret\n" : : :);

#define wfe() __asm__ __volatile__("wfe\n" : : :);

#define wfi() __asm__ __volatile__("wfi\n" : : :);

#define icialluis() __asm__ __volatile__("ic	ialluis\n" : : : "memory" );

#define per_cpu_ptr(ptr, cpu)                                                  \
	((typeof(ptr))((char *)(ptr) + (4 * sizeof(long)) * cpu))

typedef enum { cold_reset = 0, warm_reset } reset_type;

extern void __inval_dcache_area(void *addr, size_t len);

#endif
