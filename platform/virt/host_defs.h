#ifndef __HOST_DEFS_H__
#define __HOST_DEFS_H__

#define PLATFORM_CORE_COUNT 8

#define HOST_VMID	0
#define KADDR_MASK	0x00FFFFFFFFFFUL
#define	STACK_SIZE	0x2000

/*
 * MPIDR_EL1 SMP CPU identifier
 */
#define PLAT_CPU_AFF_MASK 0xFF
#define PLAT_CPU_AFF_SHIFT 0

#endif /*__HOST_DEFS_H__*/
