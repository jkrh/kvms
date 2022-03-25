/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __HYP_CONFIG_H__
#define __HYP_CONFIG_H__

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
#ifndef HOST_DATA_CONTEXT
#error HOST_DATA_CONTEXT not defined, check your config!
#endif
#ifndef HOST_CONTEXT_VCPU
#error HOST_CONTEXT_VCPU not defined, check your config!
#endif
#ifndef VCPU_VCPUIDX
#error VCPU_VCPUIDX not defined, check your config!
#endif
#ifndef VCPU_CONTEXT
#error VCPU_CONTEXT not defined, check your config!
#endif
#ifndef CPU_HOST_SP
#error CPU_HOST_SP not defined, check your config!
#endif
#ifndef KVM_ARCH_VTCR
#error KVM_ARCH_VTCR not defined, check your config!
#endif
#else // STANDALONE
#define	KVM_ARCH		0
#define	KVM_ARCH_VMID		0
#define	KVM_ARCH_PGD		0
#define	KVM_EXT_OPS		0
#define	HOST_DATA_CONTEXT	0
#define	HOST_CONTEXT_VCPU	0
#define	VCPU_VCPUIDX		0
#define	VCPU_CONTEXT		0
#define	CPU_HOST_SP		0
#define	KVM_ARCH_VTCR		0
#endif // STANDALONE

#endif // __HYP_CONFIG_H__
