// SPDX-License-Identifier: GPL-2.0-only
#include <stdint.h>
#include <sys/types.h>
#include <host_platform.h>

#include "psci.h"
#include "guest.h"
#include "helpers.h"
#include "hyplogs.h"
#include "hvccall.h"
#include "spinlock.h"

/*
 * TODO: Add implementation to UART driver to check whether clocks are
 * enabled. Meanwhile be careful when adding printfs at this function.
 * UART clocks may have been turned off before calling this function.
 * For example PSCI_CPU_ON_SMC64 is called with UART clocks off.
 */
void psci_reg(u_register_t cn, u_register_t a1, u_register_t a2,
	      u_register_t a3, u_register_t a4, u_register_t a5)
{
	uint64_t vmid, cpuid, target_core, maxcpu, hcr_el2;
	kvm_guest_t *guest;
	kernel_func_t **cpu_map;

	vmid = get_current_vmid();
	if (vmid == HOST_VMID)
		maxcpu = PLATFORM_CORE_COUNT;
	else
		maxcpu = NUM_VCPUS;

	guest = get_guest(vmid);
	if (!guest)
		return;

	cpu_map = guest->cpu_map;
	cpuid = smp_processor_id();

	/*
	 * Need for this lock is a bit questionable - but for now want to
	 * play safe so that we can never be turning things on and off in
	 * parallel.
	 */
	lock_guest(guest);

	switch (cn) {
	case PSCI_FEATURES:
		if (vmid != HOST_VMID)
			LOG("VMID %lu psci features\n", vmid);
		break;
	case PSCI_VERSION:
		if (vmid != HOST_VMID) {
			LOG("VMID %lu running core: %lu\n", vmid, cpuid);
			update_guest_state(GUEST_RUNNING);
			init_global_area(guest);
		}
		set_lockflags(HOST_KVM_TRAMPOLINE_LOCK, 0, 0, 0);
		break;
	case PSCI_CPU_SUSPEND:
	case PSCI_CPU_SUSPEND_SMC64:
		if (vmid == HOST_VMID) {
			cpu_map[cpuid] = (kernel_func_t *)a2;
			hcr_el2 = read_reg(HCR_EL2);
			if ((hcr_el2 & 0x80000000) == 0)
				LOG("suspend %lx\n", hcr_el2);
		} else
			LOG("VMID %u core %d suspend\n", vmid, cpuid);
		break;
	case PSCI_CPU_OFF:
		cpu_map[cpuid] = 0x0;
		break;
	case PSCI_CPU_ON:
	case PSCI_CPU_ON_SMC64:
		if (vmid == HOST_VMID)
			/* a1: target core MPIDR */
			target_core = (a1 & (0x700)) >> 8;
		else {
			/* a1: the core number */
			target_core = a1;
			LOG("VMID %u core %d cpu on\n", vmid, cpuid);
		}
		if (target_core < maxcpu) {
			/* a2 has the core entry address */
			cpu_map[target_core] = (kernel_func_t *)a2;
			dmb();
		}
		break;
	case PSCI_SYSTEM_OFF:
		if (vmid != HOST_VMID) {
			LOG("VMID %lu system power off\n", vmid);
			update_guest_state(GUEST_RESET);
		}
		break;
	case PSCI_SYSTEM_RESET:
	case PSCI_SYSTEM_RESET2:
	case PSCI_SYSTEM_RESET_SMC64:
		if (vmid != HOST_VMID) {
			LOG("VMID %lu system reset\n", vmid);
			update_guest_state(GUEST_RESET);
		}
		break;
	case PSCI_SYSTEM_SUSPEND:
	case PSCI_SYSTEM_SUSPEND_SMC64:
		if (vmid != HOST_VMID)
			LOG("VMID %lu system suspend\n", vmid);
		break;
	case PSCI_MIGRATE_INFO_TYPE:
		if (vmid != HOST_VMID)
			LOG("VMID %lu migrate info type\n", vmid);
		break;
	case ARM_SMCCC_ARCH_WORKAROUND_1:
	case ARM_SMCCC_ARCH_WORKAROUND_2:
	case ARM_SMCCC_ARCH_WORKAROUND_3:
		break;
	default:
		if (vmid != HOST_VMID)
			ERROR("VMID %lu unknown PSCI call %lx\n", vmid, cn);
		break;
	}

	unlock_guest(guest);
}
