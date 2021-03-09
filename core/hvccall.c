// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <host_platform.h>

#include "include/generated/asm-offsets.h"
#include "armtrans.h"
#include "bits.h"
#include "helpers.h"
#include "spinlock.h"
#include "hvccall.h"
#include "psci.h"
#include "guest.h"
#include "hyplogs.h"
#include "heap.h"
#include "mm.h"

#define CALL_TYPE_UNKNOWN	0
#define CALL_TYPE_HOSTCALL	1
#define CALL_TYPE_GUESTCALL	2
#define CALL_TYPE_KVMCALL	3

#define TTBR_BADDR_MASK     0x0000FFFFFFFFFFFEUL

typedef int hyp_func_t(void *, ...);
typedef int kvm_func_t(uint64_t, ...);

extern uint64_t __kvm_host_data[PLATFORM_CORE_COUNT];
extern hyp_func_t *__guest_exit;
hyp_func_t *__fpsimd_guest_restore;
extern uint64_t hyp_text_start;
extern uint64_t hyp_text_end;
extern uint64_t core_lock;
uint64_t crash_lock;

static int is_apicall(uint64_t cn)
{
	if ((cn >= HYP_FIRST_GUESTCALL) &&
	    (cn <= HYP_LAST_GUESTCALL))
		return CALL_TYPE_HOSTCALL;
	if ((cn >= HYP_FIRST_HOSTCALL) &&
	    (cn <= HYP_LAST_HOSTCALL))
		return CALL_TYPE_GUESTCALL;
	return CALL_TYPE_UNKNOWN;
}

int hvccall(register_t cn, register_t a1, register_t a2, register_t a3,
	    register_t a4, register_t a5, register_t a6, register_t a7,
	    register_t a8, register_t a9)
{
	int64_t res = -EINVAL;
	uint64_t addr;

	if (is_apicall(cn))
		spin_lock(&core_lock);

	switch (cn) {
	/*
	 * Stage 1 and 2 host side mappings
	 */
	case HYP_HOST_MAP_STAGE1:
		/*
		 * If we assume that for now our guest is always virt,
		 * and virt has the device area below 0x4000 0000, we
		 * can hardcode the type.
		 */
		if (a2 < 0x40000000)
			a5 = DEVICE_GRE;
		else
			a5 = NORMAL_MEMORY;

		res = mmap_range(NULL, STAGE1, a1, a2, a3, a4, a5);
		/*
		 * kern_hyp_va: MSB WATCH
		 *
		LOG("HYP_HOST_MAP_STAGE1: %ld: 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n",
		     res, a1, a2, a3, a4, a5);
		 */
#ifdef HOSTBLINDING_DEV
		/*
		 * Workaround. Keep mappings of the sections mapped to
		 * el2 intact. Guest appears to map a piece of memory
		 * from a kernel (bss) location mapped by KVM (for still
		 * unknown reason).
		 * We can't make this part of memory unreachable by host.
		 */
		if (add_kvm_hyp_region(a1, a2, a3))
			HYP_ABORT();
#endif // HOSTBLINDING_DEV
		break;
	case HYP_HOST_UNMAP_STAGE1:
		res = unmap_range(NULL, STAGE1, a1, a2);

#ifdef HOSTBLINDING_DEV
		if (remove_kvm_hyp_region(a1))
			ERROR("kvm hyp region not found! %lx\n", a1);
#endif // HOSTBLINDING_DEV
		break;
	case HYP_HOST_MAP_STAGE2:
		res = mmap_range(NULL, STAGE2, a1, a2, a3, a4, a5);
		break;
	case HYP_HOST_BOOTSTEP:
	/*	res = hyp_bootstep(a1, a2, a3, a4, a5, a6);*/
		res = 0;
		break;
	case HYP_HOST_GET_VMID:
		res = platform_get_next_vmid(a1);
		break;
	case HYP_HOST_SET_LOCKFLAGS:
		res = set_lockflags(a1);
		break;

#ifdef KVM_GUEST_SUPPORT
	uint64_t *pte = NULL;
	hyp_func_t *func;
	kvm_guest_t *guest = NULL;

	/*
	 * Control functions
	 */
	case HYP_READ_MDCR_EL2:
		res = read_reg(MDCR_EL2);
		break;
	case HYP_SET_HYP_TXT:
		hyp_text_start = (uint64_t)kern_hyp_va((void *)a1);
		hyp_text_end = (uint64_t)kern_hyp_va((void *)a2);
		LOG("hyp text is at 0x%lx - 0x%lx\n",
			hyp_text_start, hyp_text_end);

		__guest_exit = (hyp_func_t *)(a3 & CALL_MASK);
		__fpsimd_guest_restore = (hyp_func_t *)(a4 & CALL_MASK);

		LOG("guest exit is at offset 0x%lx\n", (uint64_t)__guest_exit);
		LOG("simd_guest_restore is at offset 0x%lx\n",
			(uint64_t)__fpsimd_guest_restore);

		res = 0;
		break;
	case HYP_SET_WORKMEM:
		res = set_heap(kern_hyp_va((void *)a1), (size_t)a2);
		break;
	case HYP_SET_TPIDR:
		if ((a2 < 0) || (a2 >= PLATFORM_CORE_COUNT)) {
			ERROR("invalid cpu id %lu\n", a2);
			break;
		}
		__kvm_host_data[a2] = (uint64_t)a3;
		write_reg(TPIDR_EL2, a1);
		res = 0;
		break;
	/*
	 * Guest functions
	 *	- s2 map to establish the machine model
	 *	- unmap, called by linux mm to reclaim pages
	 *	- init, free guest
	 */
	case HYP_GUEST_MAP_STAGE2:
		guest = get_guest(a1);
		if (!guest) {
			res = -ENOENT;
			break;
		}
		res = guest_map_range(guest, a2, a3, a4, a5, a6);
		break;
	case HYP_GUEST_UNMAP_STAGE2:
		guest = get_guest(a1);
		if (!guest) {
			res = -ENOENT;
			break;
		}
		res = guest_unmap_range(guest, a2, a3, a4);
		break;
	case HYP_MKYOUNG:
		guest = get_guest(a1);
		if (!guest) {
			res = -ENOENT;
			break;
		}
		addr = pt_walk(guest->s2_pgd, a2, &pte, GUEST_TABLE_LEVELS);
		if (addr != ~0UL) {
			bit_set(*pte, AF_BIT);
			res = 0;
		} else
			res = -ENOENT;
		break;
	case HYP_INIT_GUEST:
		res = init_guest((void *)a1);
		break;
	case HYP_FREE_GUEST:
		res = free_guest((void *)a1);
		break;
	case HYP_UPDATE_GUEST_MEMSLOT:
		res = update_memslot((void *)a1, (kvm_memslot *)a2,
				     (kvm_userspace_memory_region *)a3);
		break;
	case HYP_USER_COPY:
		res = guest_user_copy(a6, a1, a2);
		break;
	case HYP_READ_LOG:
		res = read_log();
		break;
	/*
	 * KVM callbacks
	 */
	default:
		cn = (uint64_t)kern_hyp_va((void *)cn);
		if ((cn >= hyp_text_start) && (cn < hyp_text_end)) {
			func = (hyp_func_t *)cn;
			res = func((void *)a1, a2, a3, a4, a5, a6, a7, a8, a9);
		} else
			ERROR("unknown hyp call 0x%lx\n", cn);
		break;
#else
	default:
		ERROR("unknown hyp call 0x%lx\n", cn);
		break;
#endif // KVM_GUEST_SUPPORT
	}
	if (is_apicall(cn))
		spin_unlock(&core_lock);

	return res;
}

void print_abort(void)
{
	kvm_guest_t *host = NULL;
	uint64_t ipa, pa, far;
	uint64_t ttbr1_el1;

	ttbr1_el1 = (read_reg(TTBR1_EL1) & TTBR_BADDR_MASK);
	host = get_guest(HOST_VMID);
	far = read_reg(FAR_EL2);

	ERROR("VTTBR_EL2 (0x%012x) ESR_EL2 (0x%012lx) FAR_EL2 (0x%012lx)\n",
	      read_reg(VTTBR_EL2), read_reg(ESR_EL2), read_reg(FAR_EL2));
	ERROR("HPFAR_EL2 (0x%012lx)\n", read_reg(HPFAR_EL2));

	ERROR("Host s2 table (0x%012lx)\n", host->s2_pgd);
	/* Walk IPA from host s1 table */
	if (ttbr1_el1 != 0) {
		ipa = pt_walk((struct ptable *)ttbr1_el1,
			       far, NULL, TABLE_LEVELS);
		/* Walk PA from host s2 table */
		pa = pt_walk((struct ptable *)host->s2_pgd,
			      ipa, NULL, TABLE_LEVELS);

		ERROR("FAR: (0x%012lx) IPA: (0x%012lx) PA: (0x%012lx)\n",
		      far, ipa, pa);
	}
}

NORETURN
void hyp_abort(const char *func, const char *file, int line)
{
	ERROR("Aborted: file %s func %s line %lu\n", func, file, line);

#ifdef CRASHDUMP
	print_tables(get_current_vmid());
#endif
	while (1)
		wfi();
}

NORETURN
void dump_state(uint64_t level, void *sp)
{
	register uint64_t faddr;
	register uint64_t stage2;
	uint64_t *__frame = (uint64_t *)sp;

	/* Try to make sure the dump stays readable */
	spin_lock(&crash_lock);

	faddr = read_reg(ELR_EL2);
	switch (level) {
	case 1:
		ERROR("Unhandled exception in EL1 at 0x%012lx\n", faddr);

		stage2 = read_reg(VTTBR_EL2) & 0xFFFFFFFFFFFEUL;
		ERROR("Mapping %012lx -> %012lx\n", faddr,
		      pt_walk((struct ptable *)stage2, faddr, NULL, TABLE_LEVELS));
		break;
	case 2:
		ERROR("Unhandled exception in EL2 at 0x%012lx\n", faddr);
		break;
	case 3:
		ERROR("Unhandled SMC trap at 0x%012lx\n", faddr);
		break;
	default:
		ERROR("Unhandled exception\n");
		break;
	}
	ERROR("VTTBR_EL2 (0x%012x) ESR_EL2 (0x%012lx) FAR_EL2 (0x%012lx)\n",
	      read_reg(VTTBR_EL2), read_reg(ESR_EL2), read_reg(FAR_EL2));
	ERROR("HPFAR_EL2 (0x%012lx)\n", read_reg(HPFAR_EL2));

	ERROR("x00(0x%012lx):x01(0x%012lx):x02(0x%012lx):x03(0x%012lx)\n",
		__frame[0], __frame[1], __frame[2], __frame[3]);
	ERROR("x04(0x%012lx):x05(0x%012lx):x06(0x%012lx):x07(0x%012lx)\n",
		__frame[4], __frame[5], __frame[6], __frame[7]);
	ERROR("x08(0x%012lx):x09(0x%012lx):x10(0x%012lx):x11(0x%012lx)\n",
		__frame[8], __frame[9], __frame[10], __frame[11]);
	ERROR("x12(0x%012lx):x13(0x%012lx):x14(0x%012lx):x15(0x%012lx)\n",
		__frame[12], __frame[13], __frame[14], __frame[15]);
	ERROR("x16(0x%012lx):x17(0x%012lx):x18(0x%012lx):x19(0x%012lx)\n",
		__frame[16], __frame[17], __frame[18], __frame[19]);
	ERROR("x20(0x%012lx):x21(0x%012lx):x22(0x%012lx):x23(0x%012lx)\n",
		__frame[20], __frame[21], __frame[22], __frame[23]);
	ERROR("x24(0x%012lx):x25(0x%012lx):x26(0x%012lx):x27(0x%012lx)\n",
		__frame[24], __frame[25], __frame[26], __frame[27]);
	ERROR("x28(0x%012lx):x29(0x%012lx):x30(0x%012lx)\n",
		__frame[28], __frame[29], __frame[30]);

#ifdef CRASHDUMP
	print_tables(get_current_vmid());
#endif
	spin_unlock(&crash_lock);
	while (1)
		wfi()
}
