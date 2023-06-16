/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Digital14 Ltd.
 *
 * Authors:
 * Konsta Karsisto <konsta.karsisto@gmail.com>
 *
 * File: hyp-drv.h
 *	Hypervisor call module for userspace
 */

#ifndef __HYP_DRV__
#define __HYP_DRV__

struct hypdrv_mem_region {
	u64 start;
	u64 end;
	u64 prot;
};

struct log_frag {
	u64 frag;
};

struct guest_key {
	char name[16];
	size_t keysize;
	unsigned char key[32];
};

struct encrypted_keys {
	u64 vmid;
	u32 len;
	char buf[1024];
};


#define KERNEL_LOCK	1
#define KERNEL_MMAP	2
#define KERNEL_WRITE	3
#define READ_LOG	4
#define GENERATE_KEY	5
#define READ_KEY	6
#define SAVE_KEYS	7
#define LOAD_KEYS	8
#define DELETE_KEY	9

#define HYPDRV_IOCTL_BASE 0xDE
#define HYPDRV_KERNEL_LOCK _IO(HYPDRV_IOCTL_BASE, 1)
#define HYPDRV_KERNEL_MMAP _IOW(HYPDRV_IOCTL_BASE, 2, struct hypdrv_mem_region)
#define HYPDRV_KERNEL_WRITE _IOW(HYPDRV_IOCTL_BASE, 3, struct hypdrv_mem_region)
#define HYPDRV_READ_LOG _IOR(HYPDRV_IOCTL_BASE, 4, struct log_frag)
#define HYPDRV_GENERATE_KEY _IOWR(HYPDRV_IOCTL_BASE, 5, struct guest_key)
#define HYPDRV_READ_KEY _IOWR(HYPDRV_IOCTL_BASE, 6, struct guest_key)
#define HYPDRV_SAVE_KEYS _IOWR(HYPDRV_IOCTL_BASE, 7, struct encrypted_keys)
#define HYPDRV_LOAD_KEYS _IOW(HYPDRV_IOCTL_BASE, 8, struct encrypted_keys)
#define HYPDRV_DELETE_KEY _IOW(HYPDRV_IOCTL_BASE, 9, struct guest_key)

#define _XN(A, B)	(A<<54|B<<53)
#define _SH(A, B)	(A<<9|B<<8)
#define _S2AP(A, B)	(A<<7|B<<6)
#define HYPDRV_KERNEL_EXEC	(_XN(1UL, 1UL)|_SH(1UL, 1UL)|_S2AP(0UL, 1UL))
#define HYPDRV_PAGE_KERNEL	(_XN(1UL, 0UL)|_SH(1UL, 1UL)|_S2AP(1UL, 1UL))
#define HYPDRV_PAGE_VDSO	(_XN(0UL, 1UL)|_SH(1UL, 1UL)|_S2AP(1UL, 1UL))
#define HYPDRV_PAGE_KERNEL_RO	(_XN(1UL, 0UL)|_SH(1UL, 1UL)|_S2AP(0UL, 1UL))

#define s2_wb (0xF << 2)	/* Outer & inner Write-Back Cacheable */

#endif // __HYP_DRV__
