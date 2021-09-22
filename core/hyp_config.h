/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __CONFIG_H__
#define __CONFIG_H__

#ifndef STANDALONE
#include "include/generated/asm-offsets.h"
/*
 * Make sure the kernel build has been properly configured
 * for KVM extension.
 */
#ifndef KVM_ARCH
#error KVM_ARCH not defined, check your config!
#endif
#ifndef KVM_ARCH_VMID
#error KVM_ARCH_VMID not defined, check your config!
#endif
#ifndef KVM_ARCH_PGD
#error KVM_ARCH_PGD not defined, check your config!
#endif
#ifndef KVM_EXT_OPS
#error KVM_EXT_OPS not defined, check your config!
#endif
#ifndef HOST_DATA_CONTEXT
#error HOST_DATA_CONTEXT not defined, check your config!
#endif
#ifndef HOST_CONTEXT_VCPU
#error HOST_CONTEXT_VCPU not defined, check your config!
#endif
#else
#define	KVM_ARCH		0
#define	KVM_ARCH_VMID		0
#define	KVM_ARCH_PGD		0
#define	KVM_EXT_OPS		0
#define	HOST_DATA_CONTEXT	0
#define	HOST_CONTEXT_VCPU	0
#endif // STANDALONE


#endif // __CONFIG_H__
