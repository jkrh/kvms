/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __HYP_API__
#define __HYP_API__
/*
 * Base addressing for data sharing
 */
#define KERNEL_MAP	0xFFFFFFF000000000UL
#define KERN_VA_MASK	0x0000000FFFFFFFFFUL
#define CALL_MASK	KERN_VA_MASK
#define KERNEL_BASE	0x4000000000UL

/*
 * Host protection support
 */
#define HYP_HOST_MAP_STAGE1		0x8000
#define HYP_HOST_MAP_STAGE2		0x8001
#define HYP_HOST_UNMAP_STAGE1		0x8002
#define HYP_HOST_UNMAP_STAGE2		0x8003
#define HYP_HOST_BOOTSTEP		0x8004
#define HYP_HOST_GET_VMID		0x8005

/*
 * KVM guest support
 */
#define HYP_READ_MDCR_EL2		0x9000
#define HYP_SET_HYP_TXT			0x9001
#define HYP_SET_TPIDR			0x9002
#define HYP_INIT_GUEST			0x9003
#define HYP_FREE_GUEST			0x9004
#define HYP_UPDATE_GUEST_MEMSLOT	0x9005
#define HYP_GUEST_MAP_STAGE2		0x9006
#define HYP_GUEST_UNMAP_STAGE2		0x9007
#define HYP_SET_WORKMEM			0x9008
#define HYP_USER_COPY			0x9009
#define HYP_MKYOUNG			0x900A

/*
 * Misc
 */
#define HYP_READ_LOG			0xA000

#define STR(x) #x
#define XSTR(s) STR(s)

#endif // __HYP_API__
