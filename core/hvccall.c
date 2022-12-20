// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <host_platform.h>

#include "hyp_config.h"
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
#include "kjump.h"
#include "validate.h"
#include "platform_api.h"
#include "gic.h"
#include "oplocks.h"
#include "crypto/platform_crypto.h"
#include "keystore.h"
#include "host.h"

#define ISS_MASK		0x1FFFFFFUL
#define ISS_RT_MASK		0x3E0UL
#define ISS_RT_SHIFT		5

#define CALL_TYPE_KVMCALL	0
#define CALL_TYPE_HOSTCALL	1
#define CALL_TYPE_GUESTCALL	2
#define CALL_TYPE_MAPCALL	4

typedef int hyp_func_t(void *, ...);
typedef int kvm_func_t(uint64_t, ...);

extern struct hyp_extension_ops eops;
extern uint64_t __kvm_host_data[PLATFORM_CORE_COUNT];
extern uint64_t hyp_text_start;
extern uint64_t hyp_text_end;
extern bool apiwarned;

hyp_func_t *__fpsimd_guest_restore DATA;
spinlock_t crash_lock;

int is_apicall(uint64_t cn)
{
	if ((cn == HYP_HOST_SWAP_PAGE) ||
	    (cn == HYP_HOST_RESTORE_SWAP_PAGE) ||
	    (cn == HYP_GUEST_UNMAP_STAGE2))
		return CALL_TYPE_MAPCALL;
	if (unlikely((cn >= HYP_FIRST_GUESTCALL) &&
		     (cn <= HYP_LAST_GUESTCALL)))
		return CALL_TYPE_GUESTCALL;
	if (unlikely((cn >= HYP_FIRST_HOSTCALL) &&
		     (cn <= HYP_LAST_HOSTCALL)))
		return CALL_TYPE_HOSTCALL;
	return CALL_TYPE_KVMCALL;
}

int64_t guest_hvccall(register_t cn, register_t a1, register_t a2, register_t a3,
		      register_t a4, register_t a5, register_t a6, register_t a7,
		      register_t a8, register_t a9)
{
	platform_crypto_ctx_t crypto_ctx;
	kvm_guest_t *guest, *host;
	int64_t res = -EINVAL;

	do_debugstop();

	guest = get_guest(get_current_vmid());
	if (unlikely(guest == NULL))
		return -EINVAL;

	host = get_guest(HOST_VMID);
	if (!host)
		panic("no host\n");

	load_host_s2();
	spin_lock(&host->hvc_lock);

	switch (cn) {
	case HYP_SET_GUEST_MEMORY_BLINDED:
		res = remove_host_range(guest, a1, a2, false);
		if (!res)
			clear_share(guest, a1, a2);
		break;
	case HYP_SET_GUEST_MEMORY_OPEN:
		res = restore_host_range(guest, a1, a2, false);
		if (res)
			goto out;

		res = set_share(guest, a1, a2);
		if (res)
			ERROR("unable to mark region %p/%d as shared\n",
			      a1, (int)a2);
		break;
	case HYP_REGION_PROTECT:
		res = guest_region_protect(guest, (uint64_t)a2,
					  (size_t)a3, (uint64_t)a4);
		break;
	case HYP_GENERATE_KEY:
		res = generate_key(guest, virt_to_phys((void *) a1),
				   virt_to_phys((void *) a2),
				   a3,
				   virt_to_phys((void *) a4));
		break;
	case HYP_GET_KEY:
		res = get_key(guest, virt_to_phys((void *) a1),
			     virt_to_phys((void *) a2),
			     a3,
			     virt_to_phys((void *) a4));
		break;
	case HYP_DELETE_KEY:
		res = delete_key(guest, a1, virt_to_phys((void *) a2));
		break;
	case HYP_DEFINE_GUEST_ID:
		guest = get_guest(a1);
		res = set_guest_id(guest, virt_to_phys((void *) a2),
				      (size_t) a3);
		break;
	case HYP_GUEST_INIT_IMAGE_CHECK:
		res = image_check_init(guest, a1);
		break;
	case HYP_GUEST_REMAP_LOADER:
		res = remap_icloader(guest, a1);
		break;
	case HYP_GUEST_DO_IMAGE_CHECK:
		RESERVE_PLATFORM_CRYPTO(&crypto_ctx);
		res = check_guest_image(guest, a1);
		RESTORE_PLATFORM_CRYPTO(&crypto_ctx);
		break;
#ifdef DEBUG
	case HYP_TRANSLATE:
		res = pt_walk(guest, STAGE2, a1, 0);
		break;
#endif
	default:
		break;
	}

out:
	spin_unlock(&host->hvc_lock);
	load_guest_s2(guest->vmid);

	return res;
}

int64_t hvccall(register_t cn, register_t a1, register_t a2, register_t a3,
		register_t a4, register_t a5, register_t a6, register_t a7,
		register_t a8, register_t a9)
{
	kvm_guest_t *guest = NULL, *host = NULL;
	platform_crypto_ctx_t crypto_ctx;
	struct hyp_extension_ops **eop;
	int64_t res = -EINVAL;
	hyp_func_t *func;
	uint32_t vmid;
	int ct;

	do_debugstop();

	ct = is_apicall(cn);
	if (unlikely((ct == CALL_TYPE_GUESTCALL) && (is_locked(HOST_KVM_CALL_LOCK))))
		return -EPERM;

	vmid = get_current_vmid();
	if (unlikely(vmid != HOST_VMID))
		return guest_hvccall(cn, a1, a2, a3, a4, a5, a6, a7, a8, a9);

	host = get_guest(HOST_VMID);
	switch (ct) {
	case CALL_TYPE_GUESTCALL:
	case CALL_TYPE_HOSTCALL:
		spin_lock(&host->hvc_lock);
		break;
	default:
		break;
	}

	switch (cn) {
	/*
	 * Stage 1 and 2 host side mappings
	 */
	case HYP_HOST_MAP_STAGE1:
		if (!a5)
			guest = host;
		else
			guest = get_guest_by_kvm((void *)a5);
		/*
		 * This is a hyp mode mapping.
		 * Validate the requested range for the host.
		 */
		if (is_locked(HOST_STAGE1_EXEC_LOCK) && (a4 & S1_PXN)) {
			ERROR("EL2S1 exec lock is set: unable to map as exec\n");
			res = -EPERM;
			break;
		}
		res = guest_validate_range(host, a1, a2, a3);
		if (!res)
			res = mmap_range(guest, EL2_STAGE1, a1, a2, a3, a4,
				 KERNEL_MATTR);
		/*
		 * kern_hyp_va: MSB WATCH
		 *
		LOG("HYP_HOST_MAP_STAGE1: %ld: 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n",
		     res, a1, a2, a3, a4, a5);
		 */
		break;
	case HYP_HOST_UNMAP_STAGE1:
		/*
		 * We currently do automatic guest residue cleaning from the
		 * EL2, so this function is obsolete. Leaving the code here
		 * anyway should the need for it arise later on.

		if (!a3)
			guest = host;
		else
			guest = get_guest_by_kvm((void *)a3);
		 *
		res = guest_validate_range(host, a1, a1, a2);
		if (!res)
			res = unmap_range(guest, EL2_STAGE1, a1, a2);
		 */
		res = 0;
		break;
	/*
	 * HYP_HOST_PREPARE_STAGE2 prepares a range of memory with an existing
	 * stage2 translation table. HYP_HOST_PREPARE_STAGE2 does not change
	 * the memory attributes as normal stage2 mapping operation may do, but
	 * instead it only tears the possible contiguous areas that interleave
	 * the range to be prepared. If the prepared area boundaries interleave
	 * with existing block mappings the block will be split to align with
	 * the mapped area.
	 *
	 * If you don't see the use for the API, don't use it. The primary use
	 * is to avoid issues with a centralized TCU during the system runtime
	 * when the mappings change.
	 *
	 * HYP_HOST_PREPARE_STAGE2 can be called with similar parameters as
	 * HYP_HOST_MAP_STAGE2.
	 */
	case HYP_HOST_PREPARE_STAGE2:
		res = guest_validate_range(host, a1, a2, a3);
		if (!res)
			res = mmap_range(host, STAGE2, a1, a2, a3, a4,
				 KEEP_MATTR);
		break;
	case HYP_HOST_MAP_STAGE2:
		res = guest_validate_range(host, a1, a2, a3);
		if (!res) {
			if (a5)
				platform_add_denyrange(a2, a3);
			res = mmap_range(host, STAGE2, a1, a2, a3, a4,
				 KERNEL_MATTR);
		}
		break;
	case HYP_HOST_BOOTSTEP:
	/*	res = hyp_bootstep(a1, a2, a3, a4, a5, a6);*/
		res = 0;
		break;
	case HYP_HOST_GET_VMID:
		res = platform_get_next_vmid(a2);
		guest_set_vmid((void *)a1, res);
		break;
	case HYP_HOST_SET_LOCKFLAGS:
		res = set_lockflags(a1, a2, a3, a4);
		break;
	case HYP_HOST_SWAP_PAGE:
		RESERVE_PLATFORM_CRYPTO(&crypto_ctx);
		res = host_swap_page(a1, a2);
		RESTORE_PLATFORM_CRYPTO(&crypto_ctx);
		break;
	case HYP_HOST_RESTORE_SWAP_PAGE:
		RESERVE_PLATFORM_CRYPTO(&crypto_ctx);
		res = host_restore_swap_page(a1, a2);
		RESTORE_PLATFORM_CRYPTO(&crypto_ctx);
		break;
	/*
	 * Control functions
	 */
	case HYP_READ_MDCR_EL2:
		res = read_reg(MDCR_EL2);
		break;
	case HYP_SET_HYP_TXT:
		if (is_locked(HOST_STAGE1_EXEC_LOCK)) {
			ERROR("Hyp text already set\n");
			res = -EPERM;
			break;
		}
		hyp_text_start = (uint64_t)kern_hyp_va((void *)a1);
		hyp_text_end = (uint64_t)kern_hyp_va((void *)a2);
		__fpsimd_guest_restore = (hyp_func_t *)(a3 & CALL_MASK);
		eop = (struct hyp_extension_ops **)virt_to_phys((void *)a4);
		*eop = &eops;

		if (hyp_text_end <= hyp_text_start)
			panic("hyp_text_end <= hyp_text_start\n");

		LOG("hyp text is at 0x%lx - 0x%lx\n", hyp_text_start,
						      hyp_text_end);
		LOG("simd_guest_restore is at offset 0x%lx\n",
			(uint64_t)__fpsimd_guest_restore);
		LOG("hyp extension is installed at 0x%lx -> 0x%lx\n", eop, *eop);
		apiwarned = false;

		set_lockflags(HOST_STAGE1_EXEC_LOCK, 0, 0, 0);
		res = 0;
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
		if ((guest->vmid < GUEST_VMID_START) ||
		    (guest->vmid == INVALID_VMID)) {
			res = -EINVAL;
			break;
		}
		res = guest_validate_range(guest, a2, a3, a4);
		if (!res) {
			RESERVE_PLATFORM_CRYPTO(&crypto_ctx);
			res = guest_map_range(guest, a2, a3, a4, a5);
			RESTORE_PLATFORM_CRYPTO(&crypto_ctx);
		}
		break;
	case HYP_GUEST_UNMAP_STAGE2:
		guest = get_guest(a1);
		if (!guest) {
			res = -ENOENT;
			break;
		}
		RESERVE_PLATFORM_CRYPTO(&crypto_ctx);
		res = guest_unmap_range(guest, a2, a3, a4);
		RESTORE_PLATFORM_CRYPTO(&crypto_ctx);
		break;
	case HYP_MKYOUNG:
	case HYP_MKOLD:
	case HYP_ISYOUNG:
		res = guest_stage2_access_flag(cn, a1, a2, a3);
		break;
	case HYP_INIT_GUEST:
		RESERVE_PLATFORM_CRYPTO(&crypto_ctx);
		res = init_guest((void *)a1);
		RESTORE_PLATFORM_CRYPTO(&crypto_ctx);
		break;
	case HYP_FREE_GUEST:
		res = free_guest((void *)a1);
		break;
	case HYP_UPDATE_GUEST_MEMSLOT:
		res = update_memslot((void *)a1, (kvm_memslot *)a2,
				     (kvm_userspace_memory_region *)a3);
		break;
	case HYP_USER_COPY:
		/*
		 * Unfinished, unsafe at the moment
		res = guest_user_copy(a6, a1, a2);
		 */
		res = -ENOTSUP;
		break;
	case HYP_TRANSLATE:
		res = -ENOTSUP;
		break;
	case HYP_SET_MEMCHUNK:
		res = guest_validate_range(host, a3, a3, a4);
		if (!res)
			res = guest_memchunk_add((void *)a1, a2, a3, a4);
		break;
	case HYP_RELEASE_MEMCHUNK:
		res = -ENOTSUP;
		break;
	case HYP_GUEST_VCPU_REG_RESET:
		res = guest_vcpu_reg_reset((void *)a1, a2);
		break;
	case HYP_GUEST_MEMMAP:
		res = guest_memmap((uint32_t)a1, (void *)a2, (size_t)a3, (void *)a4,
				   (size_t)a5);
		break;
	case HYP_STOP_GUEST:
		guest = get_guest(a1);
		if (!guest) {
			res = -EINVAL;
			break;
		}
		guest->state = GUEST_STOPPED;
		break;
	case HYP_RESUME_GUEST:
		guest = get_guest(a1);
		if (!guest) {
			res = -EINVAL;
			break;
		}
		guest->state = GUEST_RUNNING;
		break;
	case HYP_GUEST_CACHE_OP:
		res = guest_cache_op(get_guest(a1), (uint64_t)a2,
				    (size_t)a3, (uint32_t)a4);
		break;
	case HYP_REGION_PROTECT:
		res = guest_region_protect(get_guest(a1), (uint64_t)a2,
					  (size_t)a3, (uint64_t)a4);
		break;
	/*
	 * Misc calls, grab lock if you need it
	 */
	case HYP_READ_LOG:
		res = read_log();
		break;
	case HYP_SYNC_GPREGS:
		res = hyp_sync_gpregs(a1, a2);
		break;
	case HYP_SAVE_KEYS:
		guest = get_guest(a1);
		RESERVE_PLATFORM_CRYPTO(&crypto_ctx);
		res = save_vm_key(guest, virt_to_phys((void *)a2), virt_to_phys((void *)a3));
		RESTORE_PLATFORM_CRYPTO(&crypto_ctx);
		break;
	case HYP_LOAD_KEYS:
		guest = get_guest(a1);
		RESERVE_PLATFORM_CRYPTO(&crypto_ctx);
		res = load_vm_key(guest, virt_to_phys((void *)a2), a3);
		RESTORE_PLATFORM_CRYPTO(&crypto_ctx);
		break;

	case HYP_GENERATE_KEY:
		res = generate_host_key(virt_to_phys((void *) a1),
				   virt_to_phys((void *) a2),
				   a3,
				   virt_to_phys((void *) a4));
		break;
	case HYP_GET_KEY:
		res = get_host_key(virt_to_phys((void *) a1),
				virt_to_phys((void *) a2),
				a3,
				virt_to_phys((void *) a4));
		break;
	/*
	 * KVM callbacks
	 */
	default:
		if (unlikely(!hyp_text_start || !hyp_text_end))
			goto out;

		if (likely(is_jump_valid(cn))) {
			cn = (uint64_t)kern_hyp_va((void *)cn);
			if (likely((cn >= hyp_text_start) && (cn < hyp_text_end))) {
				func = (hyp_func_t *)cn;
				res = func((void *)a1, a2, a3, a4, a5, a6, a7, a8, a9);
			} else
				panic("call 0x%lx not in the kvm window\n", cn);
		} else
			panic("illegal kvm jump to 0x%lx\n", cn);
		break;
	}

out:
	switch (ct) {
	case CALL_TYPE_GUESTCALL:
	case CALL_TYPE_HOSTCALL:
		spin_unlock(&host->hvc_lock);
		break;
	default:
		break;
	}

	return res;
}

void print_abort(void)
{
	kvm_guest_t *host = NULL;
	uint64_t pa, far;

	host = get_guest(HOST_VMID);
	if (!host)
		while (1)
			wfi();

	far = read_reg(FAR_EL2);

	ERROR("VTTBR_EL2 (0x%016x) ESR_EL2 (0x%016lx) FAR_EL2 (0x%016lx)\n",
	      read_reg(VTTBR_EL2), read_reg(ESR_EL2), read_reg(FAR_EL2));
	ERROR("HPFAR_EL2 (0x%016lx)\n", read_reg(HPFAR_EL2));

	ERROR("HOST STAGE1 (0x%016lx), STAGE2 (0x%016lx)\n", host->EL1S1_1_pgd,
	      host->EL1S2_pgd);

	pa = pt_walk(host, STAGEA, far, NULL);
	ERROR("FAR: (0x%016lx) PA: (0x%016lx)\n", far, pa);
}

NORETURN
void hyp_abort(const char *func, const char *file, int line,
               const char *fmt, ...)
{
	va_list args;
	char buf[128];

	ERROR("===========================================================\n");
	ERROR("Hypervisor aborted at %s:%lu in function %s:\n",
	       file, line, func);

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	va_end(args);
	ERROR(buf);
	ERROR("===========================================================\n");

#if defined(CRASHDUMP) && defined(DEBUG)
	print_mappings(get_current_vmid(), STAGE2);
	print_mappings_el2();
#endif
	while (1)
		wfi();
}

void print_regs(void *regs)
{
	uint64_t *__frame = (uint64_t *)regs;

	ERROR("x00(0x%016lx):x01(0x%016lx):x02(0x%016lx):x03(0x%016lx)\n",
		__frame[0], __frame[1], __frame[2], __frame[3]);
	ERROR("x04(0x%016lx):x05(0x%016lx):x06(0x%016lx):x07(0x%016lx)\n",
		__frame[4], __frame[5], __frame[6], __frame[7]);
	ERROR("x08(0x%016lx):x09(0x%016lx):x10(0x%016lx):x11(0x%016lx)\n",
		__frame[8], __frame[9], __frame[10], __frame[11]);
	ERROR("x12(0x%016lx):x13(0x%016lx):x14(0x%016lx):x15(0x%016lx)\n",
		__frame[12], __frame[13], __frame[14], __frame[15]);
	ERROR("x16(0x%016lx):x17(0x%016lx):x18(0x%016lx):x19(0x%016lx)\n",
		__frame[16], __frame[17], __frame[18], __frame[19]);
	ERROR("x20(0x%016lx):x21(0x%016lx):x22(0x%016lx):x23(0x%016lx)\n",
		__frame[20], __frame[21], __frame[22], __frame[23]);
	ERROR("x24(0x%016lx):x25(0x%016lx):x26(0x%016lx):x27(0x%016lx)\n",
		__frame[24], __frame[25], __frame[26], __frame[27]);
	ERROR("x28(0x%016lx):x29(0x%016lx):x30(0x%016lx)\n",
		__frame[28], __frame[29], __frame[30]);
}

NORETURN
void dump_state(uint64_t level, void *sp)
{
	register uint64_t faddr;

	/* Try to make sure the dump stays readable */
	spin_lock(&crash_lock);

	faddr = read_reg(ELR_EL2);
	switch (level) {
	case 1:
		ERROR("UNHANDLED EXCEPTION IN EL1 AT 0x%016lx\n", faddr);
		break;
	case 2:
		ERROR("UNHANDLED EXCEPTION IN EL2 AT 0x%016lx\n", faddr);
		break;
	case 3:
		ERROR("UNHANDLED SMC TRAP AT 0x%016lx\n", faddr);
		break;
	default:
		ERROR("UNHANDLED UNKNOWN EXCEPTION\n");
		break;
	}
	ERROR("VTTBR_EL2 (0x%016lx)    ESR_EL2 (0x%016lx)     FAR_EL2 (0x%016lx)\n",
	      read_reg(VTTBR_EL2), read_reg(ESR_EL2), read_reg(FAR_EL2));
	ERROR("HPFAR_EL2 (0x%016lx)  GICD_STATUSR (0x%016lx)  SPSR_EL2(0x%016lx)\n",
	      read_reg(HPFAR_EL2), read_gicdreg(GICD_STATUSR), read_reg(SPSR_EL2));
	ERROR("\n");
	print_regs(sp);

	switch (level) {
	case 1:
		print_mappings(get_current_vmid(), STAGE2);
		break;
	case 2:
		print_mappings_el2();
		break;
	default:
		break;
	}

	spin_unlock(&crash_lock);
	while (1)
		wfi();
}

void memctrl_exec(uint64_t *sp)
{
	uint64_t esr_el2, iss, rt, ipa, elr;
	uint32_t vmid, cid, inst;
	kvm_guest_t *guest;

	esr_el2 = read_reg(ESR_EL2);
	iss = esr_el2 & ISS_MASK;
	rt = (iss & ISS_RT_MASK) >> ISS_RT_SHIFT;
	cid = smp_processor_id();
	vmid = get_current_vmid();

	do_debugstop();

#ifdef SYSREG_PRINT
	spin_lock(&crash_lock);
#endif
	/*
	 * ISS encoding:
	 * 24  |     |     |     |   5|    1|          0|
	 * Op0 | Op2 | Op1 | CRn | Rt | CRm | Direction |
	 *
	 * TVM trap registers:
	 * SCTLR_EL1, TTBR0_EL1, TTBR1_EL1, TCR_EL1, ESR_EL1, FAR_EL1,
	 * AFSR0_EL1, AFSR1_EL1, MAIR_EL1, AMAIR_EL1, CONTEXTIDR_EL1.
	 */
	iss &= ~(0x1F << 5);
	switch (iss) {
	case 0x300400:
		PRINTREG("vmid %u core %u sctlr_el1 0x%lx\n", vmid, cid, sp[rt]);
		write_reg(SCTLR_EL1, sp[rt]);
		break;
	case 0x300800:
		PRINTREG("vmid %u core %u ttbr0_el1 0x%lx\n", vmid, cid, sp[rt]);
		write_reg(TTBR0_EL1, sp[rt]);
		break;
	case 0x320800:
		PRINTREG("vmid %u core %u ttbr1_el1 0x%lx\n", vmid, cid, sp[rt]);
		write_reg(TTBR1_EL1, sp[rt]);
		break;
	case 0x340800:
		PRINTREG("vmid %u core %u tcr_el1 0x%lx\n", vmid, cid, sp[rt]);
		write_reg(TCR_EL1, sp[rt]);
		break;
	case 0x302804:
		PRINTREG("vmid %u core %u mair_el1 0x%lx\n", vmid, cid, sp[rt]);
		write_reg(MAIR_EL1, sp[rt]);
		break;
	case 0x301800:
		PRINTREG("vmid %u core %u far_el1 0x%lx\n", vmid, cid, sp[rt]);
		write_reg(FAR_EL1, sp[rt]);
		break;
	case 0x323400:
		PRINTREG("vmid %u core %u contextidr_el1 0x%lx\n", vmid, cid, sp[rt]);
		write_reg(CONTEXTIDR_EL1, sp[rt]);
		break;
	case 0x301404:
		PRINTREG("vmid %u core %u esr_el1 0x%lx\n", vmid, cid, sp[rt]);
		write_reg(ESR_EL1, sp[rt]);
		break;
	/* Unused by Linux below */
	case 0x301402:
		PRINTREG("vmid %u core %u afsr0_el1 0x%lx\n", vmid, cid, sp[rt]);
		write_reg(AFSR0_EL1, sp[rt]);
		break;
	case 0x321402:
		PRINTREG("vmid %u core %u afsr1_el1 0x%lx\n", vmid, cid, sp[rt]);
		write_reg(AFSR1_EL1, sp[rt]);
		break;
	case 0x302806:
		PRINTREG("vmid %u core %u amair_el1 0x%lx\n", vmid, cid, sp[rt]);
		write_reg(AMAIR_EL1, sp[rt]);
		break;
	default:
		guest = get_guest(vmid);
		elr = read_reg(ELR_EL2);
		ipa = pt_walk(guest, STAGE2, elr, 0);

		ERROR("UNHANDLED TRAP AT %p, ipa %p\n", elr, ipa);
		ERROR("VMID %u CORE %u ESR 0x%016lx ISS 0x%08X\n", vmid, cid,
		      esr_el2, iss);
		inst = (uint32_t)*(uint64_t *)ipa;
		ERROR("Failing instruction was 0x%x\t'n", inst);
		ERROR("https://armconverter.com/?disasm&code=%x\n", inst);
		panic("");
		break;
	}

#ifdef SYSREG_PRINT
	spin_unlock(&crash_lock);
#endif
}

#ifdef GUESTDEBUG
int hyp_sync_gpregs(uint64_t a1, uint64_t a2)
{
	struct vcpu_context *res;

	res = (struct vcpu_context *)eops.hyp_vcpu_regs(a1, a2);
	if (res) {
		memcpy(res->kvm_regs, &res->regs, sizeof(struct user_pt_regs));
		return 0;
	}

	return -EFAULT;
}
#endif

