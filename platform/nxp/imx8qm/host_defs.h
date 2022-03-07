#ifndef __HOST_DEFS_H__
#define __HOST_DEFS_H__

#ifndef PLATFORM_CORE_COUNT
#define PLATFORM_CORE_COUNT	6
#endif

#define HOST_VMID		3
#define GUEST_VMID_START	32
#define PRODUCT_VMID_MAX	255
#define KADDR_MASK		0x007FFFFFFFFFUL

#define	STACK_SIZE		0x2000

#define PLATFORM_VA_BITS	39 /* 2^39 == 512GiB */
#define T0SZ_VAL		(64 - PLATFORM_VA_BITS)

/*
 * Stage 2 translation control
 *
 * PS, bits [18:16] 0b010 40 bits, 1TB.
 * TG0, bits [15:14]
 * 		4K granule
 * SH0[13:12] Inner shareable
 * ORGN0, bits [11:10] 0b01 Normal memory,
 * 		Outer Write-Back Read-Allocate Write-Allocate Cacheable.
 * IRGN0, bits [9:8] 0b01 Normal memory,
 * 		Inner Write-Back Read-Allocate Write-Allocate Cacheable.
 * - 40 bit 2nd stage translation pass
 * SL0, bits [7:6]
 * 		In all cases, for a stage 2 translation,
 * 		the VTCR_EL2.SL0 field must indicate the required initial
 * 		lookup level, and this level must be consistent with the
 * 		value of the VTCR_EL2.T0SZ field
 * T0SZ, bits [5:0] (memory region addressed by VTTBR_EL2.
 * 		The region size is 2^(64-T0SZ) bytes)
 */
#define PLATFORM_VTCR_EL2	(0x80023540 | T0SZ_VAL)

/*
 * Stage 1 translation control
 *
 * PS[18:16] 0b010 40 bits, 1TB.
 * 		Physical address Size for the Second Stage of translation.
 * 4K granule
 * SH0[13:12] Inner shareable
 * ORGN0, bits [11:10] 0b01 Normal memory,
 * 		Outer Write-Back Read-Allocate Write-Allocate Cacheable.
 * IRGN0, bits [9:8] 0b01 Normal memory,
 * 		Inner Write-Back Read-Allocate Write-Allocate Cacheable.
 * T0SZ, bits [5:0] (memory region addressed by TTBR0_EL2.
 * 		The region size is 2^(64-T0SZ) bytes)
 *
 */
#define PLATFORM_TCR_EL2	(0x80823500 | T0SZ_VAL)

/*
 * MAIR_EL2 assignment from kernel
 *
 * ATTR7H Device memory                                            ATTR7L Device memory
 * ATTR6H Device memory                                            ATTR6L Write-Back non-transient
 * ATTR5H Device memory                                            ATTR5L Non-Cacheable
 * ATTR4H Device memory                                            ATTR4L Device memory
 * ATTR3H Write-Through non-transient/Write-Allocate/Read-Allocate ATTR3L Write-Through non-transient/Write-Allocate/Read-Allocate
 * ATTR2H Non-Cacheable                                            ATTR2L Non-Cacheable
 * ATTR1H Write-Back non-transient/Write-Allocate/Read-Allocate    ATTR1L Write-Back non-transient/Write-Allocate/Read-Allocate
 * ATTR0H Write-Back non-transient/Write-Allocate/Read-Allocate    ATTR0L Write-Back non-transient/Write-Allocate/Read-Allocate
 */
#define PLATFORM_MAIR_EL2	0x000C0400BB44FFFF
#define PLAT_NORMAL_WBACK_P	0
#define PLAT_NORMAL_NOCACHE	2
#define PLAT_NORMAL_WT_P	3
#define PLAT_DEVICE_STRONGORDER	4
#define PLAT_DEVICE_ORDER	5
#define PLAT_DEVICE_GRE		6

#define GIC_DIST_ADDR	0x51a00000UL
#define GIC_DIST_SZ	0x10000

#endif /*__HOST_DEFS_H__*/
