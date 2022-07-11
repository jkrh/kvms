// SPDX-License-Identifier: GPL-2.0-only
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "helpers.h"
#include "guest.h"
#include "armtrans.h"
#include "hvccall.h"
#include "mhelpers.h"
#include "mm.h"
#include "bits.h"
#include "tables.h"
#include "cache.h"
#include "pt_regs.h"
#include "spinlock.h"
#include "validate.h"
#include "arm-sysregs.h"
#include "linuxdefines.h"

#include "platform_api.h"
#include "host_platform.h"
#include "hyp_config.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"
#include "mbedtls/platform.h"

extern struct mbedtls_entropy_context mbedtls_entropy_ctx;
extern spinlock_t core_lock;

#define CHECKRES(x) if (x != MBEDTLS_EXIT_SUCCESS) return -EFAULT;
#define ARMV8_PMU_USERENR_MASK 0xf

extern struct mbedtls_ctr_drbg_context ctr_drbg;

#ifndef KVM_ARCH_VMID_OFFT
#pragma message("KVM_ARCH_VMID_OFFT not defined! Setting to zero.")
#define KVM_ARCH_VMID_OFFT 0
#endif

#define _KVM_GET_ARCH(x) ((char *)x + KVM_ARCH)
#define _KVM_GET_VMID(x) (_KVM_GET_ARCH((char *)x) + \
			  KVM_ARCH_VMID + KVM_ARCH_VMID_OFFT)

#define KVM_GET_VMID(x) (*(uint32_t *)_KVM_GET_VMID(x))
#define KVM_GET_PGD_PTR(x) ((uint64_t *)(_KVM_GET_ARCH((char *)x) + KVM_ARCH_PGD))
#define KVM_GET_VTCR(x) (*(uint64_t *)(_KVM_GET_ARCH((char *)x) + KVM_ARCH_VTCR))

#define INVALID_GUEST	MAX_VM

#define VCPU_GET_KVM(vcpu) kern_hyp_va(*(void **)((char *)(vcpu) + 0))
#define VCPU_GET_VMID(vcpu) KVM_GET_VMID(VCPU_GET_KVM(vcpu))
#define VCPU_GET_VCPUID(vcpu) (*(int *)((char *)(vcpu) + VCPU_VCPUIDX))
#define VCPU_GET_REGS(vcpu) ((struct user_pt_regs *) \
			     ((char *)(vcpu) + VCPU_CONTEXT))

#define ARM_EXCEPTION_HYP_GONE 0xbadca11

extern uint64_t hyp_guest_enter(void *vcpu, struct user_pt_regs *regs);

/*
 * Error Syndrome Register decoding
 */
#define ESR_EC(esr)          ((esr) >> 26)
#define ISS_SYSREG_RT(esr)   (((esr) & 0x3e0) >> 5)
#define ISS_SYSREG_DIR(esr)  (!!((esr) & 0x1))

#define ISS_SYSREG_OP0(esr)  (((esr) & 0x300000) >> 20)
#define ISS_SYSREG_OP2(esr)  (((esr) & 0xE0000) >> 17)
#define ISS_SYSREG_OP1(esr)  (((esr) & 0x1C000) >> 14)
#define ISS_SYSREG_CRN(esr)  (((esr) & 0x3C00) >> 10)
#define ISS_SYSREG_CRM(esr)  (((esr) & 0x1E) >> 1)
/* System register name, encoded in the "o0:op1:CRn:CRm:op2 */
#define ISS_SYSREG_NAME(esr)  (					\
			      (ISS_SYSREG_OP0(esr) << 14) |	\
			      (ISS_SYSREG_OP1(esr) << 10) |	\
			      (ISS_SYSREG_CRN(esr) << 7) |	\
			      (ISS_SYSREG_CRM(esr) << 3) |	\
			      ISS_SYSREG_OP2(esr)		\
			      )

#define ISS_DABT_ISV(esr)    (!!((esr) & 0x1000000))
#define ISS_DABT_SRT(esr)    (((esr) & 0x1f0000) >> 16)
#define ISS_DABT_WNR(esr)    (!!((esr) & 0x40))

#define MPIDR_LEVEL_BITS_SHIFT  3
#define MPIDR_LEVEL_SHIFT(level) \
	(((1 << level) >> 1) << MPIDR_LEVEL_BITS_SHIFT)

static uint16_t guest_index[PRODUCT_VMID_MAX] ALIGN(16);
kvm_guest_t guests[MAX_VM] ALIGN(16);
uint16_t last_guest_index ALIGN(16);

void format_guest(int i)
{
	int c;

	guests[i].vmid = INVALID_VMID;
	guests[i].el2_tablepool.currentchunk = GUEST_MEMCHUNKS_MAX;
	guests[i].el2_tablepool.firstchunk = GUEST_MEMCHUNKS_MAX;
	guests[i].s2_tablepool.currentchunk = GUEST_MEMCHUNKS_MAX;
	guests[i].s2_tablepool.firstchunk = GUEST_MEMCHUNKS_MAX;
	guests[i].patrack.trailpool.currentchunk = GUEST_MEMCHUNKS_MAX;
	guests[i].patrack.trailpool.firstchunk = GUEST_MEMCHUNKS_MAX;
	_zeromem16(guests[i].mempool, sizeof(guests[i].mempool));
	for (c = 0; c < GUEST_MEMCHUNKS_MAX; c++) {
		guests[i].mempool[c].type = GUEST_MEMCHUNK_UNDEFINED;
		guests[i].mempool[c].next = GUEST_MEMCHUNKS_MAX;
		guests[i].mempool[c].previous = GUEST_MEMCHUNKS_MAX;
	}
}

int load_host_s2(void)
{
	sys_context_t *host_ctxt;

	host_ctxt = &guests[guest_index[HOST_VMID]].ctxt[smp_processor_id()];

	write_reg(VTCR_EL2, host_ctxt->vtcr_el2);
	write_reg(VTTBR_EL2, host_ctxt->vttbr_el2);
	return 0;
}

int load_guest_s2(uint64_t vmid)
{
	kvm_guest_t *guest;
	sys_context_t *host_ctxt;

	host_ctxt = &guests[guest_index[HOST_VMID]].ctxt[smp_processor_id()];

	guest = &guests[guest_index[vmid]];
	if (guest == NULL) {
		ERROR("No guest for vmid %d\n", vmid);
		return -ENOENT;
	}

	host_ctxt->vtcr_el2 = read_reg(VTCR_EL2);
	host_ctxt->vttbr_el2 = read_reg(VTTBR_EL2);
	write_reg(VTTBR_EL2, guest->ctxt[0].vttbr_el2);

	return 0;
}

int guest_memmap(uint32_t vmid, void *gaddr, size_t pc, void *addr, size_t addrlen)
{
	kvm_guest_t *guest;
	uint64_t paddr;
	void *tmp;
	int n = 0;

	if (!gaddr || !pc || !addr || !addrlen)
		return -EINVAL;

	addr = virt_to_phys(addr);
	if (addr == (void *)~0UL)
		return -EINVAL;

	guest = get_guest(vmid);
	if (!guest)
		return -ENOENT;

	if (guest->state != GUEST_STOPPED)
		return -EBUSY;

	if (pc >= (addrlen * 8))
		return -EINVAL;

	memset(addr, 0, addrlen);

	tmp = gaddr;
	while (n < pc) {
		paddr = pt_walk(guest, STAGE2, (uint64_t)tmp, NULL);
		if (paddr != ~0UL)
			set_bit_in_mem(n, addr);

		n++;
		tmp += PAGE_SIZE;
	}

	return 0;
}

void save_host_traps(void)
{
	sys_context_t *host_ctxt;

	host_ctxt = &guests[guest_index[HOST_VMID]].ctxt[smp_processor_id()];

	host_ctxt->hcr_el2 = read_reg(HCR_EL2);
	host_ctxt->cptr_el2 = read_reg(CPTR_EL2);
	host_ctxt->mdcr_el2 = read_reg(MDCR_EL2);
	host_ctxt->hstr_el2 = read_reg(HSTR_EL2);
}

void restore_host_traps(void)
{
	sys_context_t *host_ctxt;

	host_ctxt = &guests[guest_index[HOST_VMID]].ctxt[smp_processor_id()];

	write_reg(HCR_EL2, host_ctxt->hcr_el2);
	write_reg(CPTR_EL2, host_ctxt->cptr_el2);
	write_reg(MDCR_EL2, host_ctxt->mdcr_el2);
	write_reg(HSTR_EL2, host_ctxt->hstr_el2 | (1 << 15));
	write_reg(PMUSERENR_EL0, ARMV8_PMU_USERENR_MASK);
	write_reg(PMSELR_EL0, 0);
}

sys_context_t *get_guest_context(uint32_t vmid, uint32_t cpuid)
{
	if (vmid >= PRODUCT_VMID_MAX || cpuid >= PLATFORM_CORE_COUNT)
		return NULL;

	if (guest_index[vmid] == INVALID_GUEST)
		return NULL;

	return &guests[guest_index[vmid]].ctxt[cpuid];
}

void *hyp_vcpu_regs(uint64_t vmid, uint64_t vcpuid)
{
	struct vcpu_context *ctxt;
	kvm_guest_t *guest = get_guest(vmid);

	if (!guest || vcpuid >= NUM_VCPUS)
		return NULL;

	ctxt = &guest->vcpu_ctxt[vcpuid];
	return &ctxt->regs;
}

uint64_t guest_enter(void *vcpu)
{
	uint64_t vmid;
	uint64_t vcpuid;
	kvm_guest_t *guest;
	struct user_pt_regs *kvm_regs;
	int reg;
	struct vcpu_context *ctxt;

	vmid = VCPU_GET_VMID(vcpu);
	vcpuid = VCPU_GET_VCPUID(vcpu);
	guest = get_guest(vmid);
	if (!guest || vcpuid >= NUM_VCPUS)
		return ARM_EXCEPTION_HYP_GONE;

	kvm_regs = VCPU_GET_REGS(vcpu);
	ctxt = &guest->vcpu_ctxt[vcpuid];
	ctxt->kvm_regs = kvm_regs;

	for (reg = 0; reg < 31; reg++)
		if (bit_raised(ctxt->gpreg_sync_from_kvm, reg))
			ctxt->regs.regs[reg] = kvm_regs->regs[reg];
	switch (ctxt->pc_sync_from_kvm) {
	case PC_SYNC_SKIP:
#ifdef GUESTDEBUG
		if (kvm_regs->pc == ctxt->regs.pc + 4)
#else
		if (kvm_regs->pc == 4)
#endif
			ctxt->regs.pc += 4;
		break;
	case PC_SYNC_COPY:
		ctxt->regs.pc = kvm_regs->pc;
		break;
	default:
		break;
	}
	ctxt->gpreg_sync_from_kvm = 0;
	ctxt->pc_sync_from_kvm = PC_SYNC_NONE;
	write_reg(ELR_EL2, ctxt->regs.pc);
	return hyp_guest_enter(vcpu, &ctxt->regs);
}

void sysreg_restore_guest(uint64_t vmid, uint64_t vcpuid)
{
	kvm_guest_t *guest;
	struct vcpu_context *ctxt;

	guest = get_guest(vmid);
	if (!guest || vcpuid >= NUM_VCPUS)
		return;

	ctxt = &guest->vcpu_ctxt[vcpuid];
	write_reg(VMPIDR_EL2, ctxt->state.mpidr_el1);
	write_reg(CSSELR_EL1, ctxt->state.csselr_el1);
	write_reg(CPACR_EL1, ctxt->state.cpacr_el1);
	write_reg(ESR_EL1, ctxt->state.esr_el1);
	write_reg(AFSR0_EL1, ctxt->state.afsr0_el1);
	write_reg(AFSR1_EL1, ctxt->state.afsr1_el1);
	write_reg(FAR_EL1, ctxt->state.far_el1);
	write_reg(VBAR_EL1, ctxt->state.vbar_el1);
	write_reg(CONTEXTIDR_EL1, ctxt->state.contextidr_el1);
	write_reg(AMAIR_EL1, ctxt->state.amair_el1);
	write_reg(CNTKCTL_EL1, ctxt->state.cntkctl_el1);
	write_reg(PAR_EL1, ctxt->state.par_el1);
	write_reg(TPIDR_EL1, ctxt->state.tpidr_el1);
	write_reg(ELR_EL1, ctxt->state.elr_el1);
	write_reg(SPSR_EL1, ctxt->state.spsr_el1);
	write_reg(SP_EL1, ctxt->state.sp_el1);
	write_reg(MDSCR_EL1, ctxt->state.mdscr_el1);
	write_reg(TPIDR_EL0, ctxt->state.tpidr_el0);
	write_reg(TPIDRRO_EL0, ctxt->state.tpidrro_el0);
}

void sysreg_save_guest(uint64_t vmid, uint64_t vcpuid)
{
	kvm_guest_t *guest;
	struct vcpu_context *ctxt;

	guest = get_guest(vmid);
	if (!guest || vcpuid >= NUM_VCPUS)
		return;

	ctxt = &guest->vcpu_ctxt[vcpuid];
	ctxt->state.csselr_el1 = read_reg(CSSELR_EL1);
	ctxt->state.tcr_el1 = read_reg(TCR_EL1);
	ctxt->state.cpacr_el1 = read_reg(CPACR_EL1);
	ctxt->state.ttbr0_el1 = read_reg(TTBR0_EL1);
	ctxt->state.ttbr1_el1 = read_reg(TTBR1_EL1);
	ctxt->state.esr_el1 = read_reg(ESR_EL1);
	ctxt->state.afsr0_el1 = read_reg(AFSR0_EL1);
	ctxt->state.afsr1_el1 = read_reg(AFSR1_EL1);
	ctxt->state.far_el1 = read_reg(FAR_EL1);
	ctxt->state.mair_el1 = read_reg(MAIR_EL1);
	ctxt->state.vbar_el1 = read_reg(VBAR_EL1);
	ctxt->state.contextidr_el1 = read_reg(CONTEXTIDR_EL1);
	ctxt->state.amair_el1 = read_reg(AMAIR_EL1);
	ctxt->state.cntkctl_el1 = read_reg(CNTKCTL_EL1);
	ctxt->state.par_el1 = read_reg(PAR_EL1);
	ctxt->state.tpidr_el1 = read_reg(TPIDR_EL1);
	ctxt->state.elr_el1 = read_reg(ELR_EL1);
	ctxt->state.spsr_el1 = read_reg(SPSR_EL1);
	ctxt->state.sp_el1 = read_reg(SP_EL1);
	ctxt->state.mdscr_el1 = read_reg(MDSCR_EL1);
	ctxt->state.tpidr_el0 = read_reg(TPIDR_EL0);
	ctxt->state.tpidrro_el0 = read_reg(TPIDRRO_EL0);
}

kvm_guest_t *get_free_guest(uint64_t vmid)
{
	kvm_guest_t *entry = NULL;
	int i;

	if ((guest_index[vmid] != INVALID_GUEST) &&
	    (vmid != 0))
		return NULL;

	for (i = 0; i < MAX_VM; i++) {
		if (guests[i].vmid == INVALID_VMID) {
			guest_index[vmid] = i;
			guests[i].index = i;
			guests[i].vmid = vmid;
			entry = &guests[i];
			break;
		}
	}
	if (!entry)
		return entry;

	for (i = 0; i < MAX_VM; i++) {
		if (guests[i].vmid != INVALID_VMID)
			last_guest_index = i + 1;
	}

	return entry;
}

kvm_guest_t *get_guest(uint64_t vmid)
{
	kvm_guest_t *guest = NULL;
	uint16_t i;

	if (vmid >= PRODUCT_VMID_MAX)
		goto out;

	i = guest_index[vmid];
	if (i != INVALID_GUEST) {
		guest = &guests[i];
		if (guest->vmid != vmid)
			guest = NULL;
	}

out:
	return guest;
}

int update_guest_state(guest_state_t state)
{
	kvm_guest_t *guest;
	uint64_t vmid;

	vmid = get_current_vmid();
	guest = get_guest(vmid);
	if (!guest)
		return -ENOENT;

	guest->state = state;
	return 0;
}

guest_state_t get_guest_state(uint64_t vmid)
{
	kvm_guest_t *guest;

	guest = get_guest(vmid);
	if (!guest)
		return GUEST_INVALID;

	return guest->state;
}

/**
 * Resolve the guest from the kvm pointer. Side effects:
 * 1. The provided kvm pointer is adjusted to the el2 address.
 * 2. The provided index is adjusted to point to the guest found in
 *    guests table.
 *
 * @param kvm the EL1 kvm structure pointer
 * @param guest_index (optional). If provided, this will be set to
 *        the index in the guests table.
 * @return pointer to guest on success or NULL on failure.
 */
static kvm_guest_t *__get_guest_by_kvm(void **kvm, int *guest_index)
{
	int i;
	kvm_guest_t *guest;

	guest = NULL;
	*kvm = kern_hyp_va(*kvm);
	for (i = 0; i < last_guest_index; i++) {
		if (guests[i].kvm == *kvm) {
			guest = &guests[i];
			break;
		}
	}

	if (guest_index != NULL)
		*guest_index = i;

	return guest;
}

kvm_guest_t *alloc_guest(void *kvm)
{
	kvm_guest_t *guest = NULL;
	uint64_t vmid = 0;

	guest = get_free_guest(vmid);

	if (guest != NULL) {
		guest->EL1S2_pgd = alloc_pgd(guest, &guest->s2_tablepool);

		if (guest->EL1S2_pgd == NULL) {
			free_guest(kvm);
			return NULL;
		}

		/*
		 * Allocate the tablepool for creating guest specific EL2 mappings.
		 */
		alloc_pgd(guest, &guest->el2_tablepool);
		if (!guest->el2_tablepool.pool) {
			free_guest(kvm);
			return NULL;
		}
		guest->kvm = kern_hyp_va(kvm);
		set_blinding_default(guest);
	}

	return guest;
}

/**
 * Walk through the provided s1 range to verify it is physically contiguous
 * and mapped in the provided s1 page global directory.
 *
 * @param guest the guest this range is checked against.
 * @param s1_pgd page global directory.
 * @param s1addr stage 1 start address of the range.
 * @param paddr optional physical start address of the range.
 *		If paddr is not provided the physical address mapped by the
 *		first stage 1 address is used instead.
 * @param len length of the range.
 * @return zero on success or negative error code on failure.
 */
bool s1_range_physically_contiguous(kvm_guest_t *guest, struct ptable *s1_pgd,
				    uint64_t s1addr, uint64_t *paddr, uint64_t len)
{
	uint64_t tvaddr, tpaddr, tlen, ttlen;

	if (paddr != NULL)
		tpaddr = *paddr;
	else
		tpaddr = pt_walk(guest, STAGEA, s1addr, 0);

	if (tpaddr == ~0UL || !len)
		return false;

	tvaddr = s1addr;
	tlen = len;
	ttlen = PAGE_SIZE;
	while (tlen > 0) {
		if (tpaddr != pt_walk(guest, STAGEA, tvaddr, 0))
			return false;

		if (tlen >= PAGE_SIZE)
			ttlen = PAGE_SIZE;
		else
			ttlen = tlen;

		tvaddr += ttlen;
		tpaddr += ttlen;
		tlen -= ttlen;
	}
	return true;
}

int __guest_memchunk_get(kvm_guest_t *guest, guest_memchunk_t *chunk)
{
	int c;

	for (c = 0; c < GUEST_MEMCHUNKS_MAX; c++) {
		if ((guest->mempool[c].start == chunk->start) &&
		    (guest->mempool[c].size == chunk->size))
			break;
	}

	if (c >= GUEST_MEMCHUNKS_MAX)
		c = -ENOENT;
	else if (guest->mempool[c].type != chunk->type)
		ERROR("wrong type!");

	return c;
}

int __guest_memchunk_add(kvm_guest_t *guest, guest_memchunk_t *chunk)
{
	int c;

	for (c = 0; c < GUEST_MEMCHUNKS_MAX; c++) {
		if (guest->mempool[c].type ==
			GUEST_MEMCHUNK_UNDEFINED) {
			guest->mempool[c].start = chunk->start;
			guest->mempool[c].size = chunk->size;
			guest->mempool[c].type = chunk->type;
			break;
		}
	}

	if (c >= GUEST_MEMCHUNKS_MAX)
		c = -ENOSPC;

	if (_zeromem16((void *)guest->mempool[c].start, guest->mempool[c].size))
		ERROR("check alignment!");

	return c;
}

int __guest_memchunk_remove(kvm_guest_t *guest, guest_memchunk_t *chunk)
{
	int c;

	c = __guest_memchunk_get(guest, chunk);
	if (c < 0)
		return c;

	if ((guest->mempool[c].type != GUEST_MEMCHUNK_FREE) ||
	    (guest->mempool[c].next != GUEST_MEMCHUNKS_MAX))
		return -EBUSY;

	if (_zeromem16((void *)guest->mempool[c].start, guest->mempool[c].size))
		ERROR("check alignment!");

	guest->mempool[c].start = 0;
	guest->mempool[c].size = 0;
	guest->mempool[c].type = GUEST_MEMCHUNK_UNDEFINED;

	return 0;
}

void guest_mempool_free(kvm_guest_t *guest)
{
	uint64_t paddr;
	size_t len;
	int c, err;

	for (c = 0; c < GUEST_MEMCHUNKS_MAX; c++) {
		paddr = guest->mempool[c].start;
		if (paddr) {
			len = guest->mempool[c].size;
			guest->mempool[c].next = GUEST_MEMCHUNKS_MAX;
			guest->mempool[c].type = GUEST_MEMCHUNK_FREE;
			err = guest_memchunk_remove(guest->kvm, paddr, len);
			if (err)
				ERROR("unable to remove %lx, err %d\n",
				      paddr, err);
		}
	}
}

int guest_memchunk_add(void *kvm, uint64_t s1addr, uint64_t paddr, uint64_t len)
{
	kvm_guest_t *host, *guest;
	struct ptable *s1_pgd;
	uint64_t tpaddr;
	guest_memchunk_t chunk;
	int res;

	if ((len < PAGE_SIZE) || (len & (PAGE_SIZE - 1)) ||
	    (paddr & (PAGE_SIZE - 1)))
		return -EINVAL;

	guest = __get_guest_by_kvm(&kvm, NULL);
	if (guest == NULL) {
		guest = alloc_guest(kvm);
		if (guest == NULL) {
			ERROR("no space to allocate a new guest\n");
			return -ENOSPC;
		}
	}

	host = get_guest(HOST_VMID);
	if (!host)
		panic("no host\n");
	/*
	 * Walk through the provided range to verify it is contiguous
	 * and physically mapped by the calling host context. This will also
	 * ensure that the result of previous guest_validate_range call is
	 * valid since we are dealing with stage1 addresses in this function.
	 */
	s1_pgd = (struct ptable *)(read_reg(TTBR1_EL1) & TTBR_BADDR_MASK);
	tpaddr = paddr;
	if (!s1_range_physically_contiguous(host, s1_pgd, s1addr, &tpaddr, len)) {
		ERROR("range is not contiguous\n");
		return -EINVAL;
	}
	res = remove_host_range(host, paddr, len, true);
	if (!res) {
		chunk.start = paddr;
		chunk.size = len;
		chunk.type = GUEST_MEMCHUNK_FREE;
		res = __guest_memchunk_add(guest, &chunk);
		if (res < 0) {
			ERROR("failed to add memchunk\n");
			return -ENOSPC;
		}
	} else {
		ERROR("remove_host_range returned: %d\n", res);
		restore_host_range(host, paddr, len, true);
		return -EINVAL;
	}

	return 0;
}

int guest_memchunk_remove(void *kvm, uint64_t paddr, uint64_t len)
{
	kvm_guest_t *host, *guest;
	guest_memchunk_t chunk;
	int res;

	guest = __get_guest_by_kvm(&kvm, NULL);
	if (guest == NULL)
		return -ENOENT;

	host = get_guest(HOST_VMID);
	if (host == NULL)
		panic("no host\n");

	res = guest_validate_range(host, paddr, paddr, len);
	if (res)
		return res;

	chunk.start = paddr;
	chunk.size = len;
	res = __guest_memchunk_remove(guest, &chunk);
	if (res)
		return res;

	return restore_host_range(host, paddr, len, true);
}

int guest_memchunk_alloc(kvm_guest_t *guest,
			 size_t minsize,
			 guest_memchunk_user_t type)
{
	int c;

	for (c = 0; c < GUEST_MEMCHUNKS_MAX; c++) {
		if ((guest->mempool[c].type == GUEST_MEMCHUNK_FREE) &&
		    (guest->mempool[c].size >= minsize)) {
			break;
		}
	}

	if (c >= GUEST_MEMCHUNKS_MAX)
		return -ENOSPC;

	guest->mempool[c].type = type;

	return c;
}

static int guest_set_table_levels(kvm_guest_t *guest, void *kvm)
{
	uint64_t vtcr_el2, t0sz;

	vtcr_el2 = KVM_GET_VTCR(kvm);

	switch (VTCR_GET_GRANULE_SIZE(vtcr_el2)) {
	case GRANULE_SIZE_4KB:
		switch (VTCR_SL0(vtcr_el2)) {
		case 0:
			guest->table_levels_el1s2 = 2;
			break;
		case 1:
			guest->table_levels_el1s2 = 3;
			break;
		case 2:
			guest->table_levels_el1s2 = 4;
			break;
		default:
			return -ENOTSUP;
		}
		break;
	/* We only support 4kB granule for now. Flow through */
	case GRANULE_SIZE_16KB:
	case GRANULE_SIZE_64KB:
	default:
		return -ENOTSUP;
	}

	t0sz = TCR_ELx_T0SZ(read_reg(TCR_EL1));
	guest->table_levels_el1s1 = s1_t0sz_to_levels(t0sz);

	t0sz = TCR_ELx_T0SZ(read_reg(TCR_EL2));
	guest->table_levels_el2s1 = s1_t0sz_to_levels(t0sz);

	if ((guest->table_levels_el1s1 == 0) ||
	    (guest->table_levels_el2s1 == 0))
		return -ENOTSUP;

	return 0;
}

const struct hyp_extension_ops eops ALIGN(16) = {
	.load_host_stage2 = load_host_s2,
	.load_guest_stage2 = load_guest_s2,
	.save_host_traps = save_host_traps,
	.restore_host_traps = restore_host_traps,
	.hyp_vcpu_regs = hyp_vcpu_regs,
	.guest_enter = guest_enter,
	.sysreg_restore_guest = sysreg_restore_guest,
	.sysreg_save_guest = sysreg_save_guest,
};

void init_guest_array(void)
{
	int i;

	for (i = 0; i < PRODUCT_VMID_MAX; i++)
		guest_index[i] = INVALID_GUEST;

	_zeromem16(guests, sizeof(guests));
	for (i = 0; i < MAX_VM; i++)
		format_guest(i);
}

int init_guest(void *kvm)
{
	kvm_guest_t *guest = NULL;
	uint64_t *pgd;
	uint8_t key[32];
	int res;

	if (!kvm)
		return -EINVAL;

	guest = __get_guest_by_kvm(&kvm, NULL);
	if (guest == NULL) {
		guest = alloc_guest(kvm);
		if (guest == NULL) {
			ERROR("no space for a new guest\n");
			return -ENOSPC;
		}
	}

	res = guest_set_table_levels(guest, kvm);
	if (res)
		return res;

	mbedtls_aes_init(&guest->aes_ctx);
	res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
				    &mbedtls_entropy_ctx, 0, 0);
	CHECKRES(res);
	res = mbedtls_ctr_drbg_random(&ctr_drbg, key, 32);
	CHECKRES(res);
	res = mbedtls_aes_setkey_enc(&guest->aes_ctx, key, 256);
	CHECKRES(res);
	res = mbedtls_aes_setkey_dec(&guest->aes_ctx, key, 256);
	CHECKRES(res);

	/*
	 * The address field (pgd ptr) set below is merely an indication to EL1
	 * that the guest has been initialized.
	 */
	pgd = KVM_GET_PGD_PTR(kvm);
	*pgd = (uint64_t)guest->EL1S2_pgd;
	guest->kvm = kvm;

	guest->vmid = KVM_GET_VMID(kvm);
	guest->ctxt[0].vttbr_el2 = (((uint64_t)guest->EL1S2_pgd) |
				    ((uint64_t)guest->vmid << 48));
	memset(guest->unique_id, 0, GUEST_UNIQUE_ID_LEN);

	/* Save the current VM process stage1 PGDs */
	guest->EL1S1_0_pgd = (struct ptable *)(read_reg(TTBR0_EL1) & TTBR_BADDR_MASK);
	guest->EL1S1_1_pgd = (struct ptable *)(read_reg(TTBR1_EL1) & TTBR_BADDR_MASK);

	dsb();
	isb();
	return 0;
}

kvm_guest_t *get_guest_by_kvm(void *kvm)
{
	kvm_guest_t *guest = NULL;

	guest = __get_guest_by_kvm(&kvm, NULL);
	if (guest == NULL)
		guest = alloc_guest(kvm);

	return guest;
}

kvm_guest_t *get_guest_by_s1pgd(struct ptable *pgd)
{
	int i;

	/* Look for the actual guests first.. */
	for (i = 0; i < last_guest_index; i++) {
		if ((guests[i].vmid != HOST_VMID) &&
		    (guests[i].EL1S1_0_pgd == pgd))
			return &guests[i];
	}
	/* And if it wasn't any, the host..  */
	for (i = 0; i < last_guest_index; i++) {
		if (guests[i].EL2S1_pgd == pgd)
			return &guests[i];
	}

	return NULL;
}

int is_share(kvm_guest_t *guest, uint64_t gpa, size_t len)
{
	return patrack_gpa_is_share(guest, gpa, len);
}

int clear_share(kvm_guest_t *guest, uint64_t gpa, size_t len)
{
	return patrack_gpa_clear_share(guest, gpa, len);
}

int set_share(kvm_guest_t *guest, uint64_t gpa, size_t len)
{
	return patrack_gpa_set_share(guest, gpa, len);
}

int is_any_share(uint64_t paddr)
{
	int i = 0;
	uint64_t gpa;

	if (paddr == ~0UL)
		return 0;

	for (i = 0; i < last_guest_index; i++) {
		if (!guests[i].vmid || (guests[i].vmid == INVALID_VMID))
			continue;

		if (guests[i].vmid < GUEST_VMID_START)
			continue;

		/* Check if guest has this address mapped */
		if (patrack(&guests[i], paddr) != paddr)
			continue;

		gpa = patrack_hpa2gpa(&guests[i], paddr);
		if (is_share(&guests[i], gpa, PAGE_SIZE) == 1)
			return 1;
	}

	return 0;
}

kvm_guest_t *get_guest_by_s2pgd(struct ptable *pgd)
{
	kvm_guest_t *guest = NULL;
	int i;

	for (i = 0; i < last_guest_index; i++) {
		if (guests[i].EL1S2_pgd == pgd) {
			guest = &guests[i];
			break;
		}
	}
	return guest;
}

int guest_set_vmid(void *kvm, uint64_t vmid)
{
	kvm_guest_t *guest = NULL;
	int i, res = -ENOENT;

	if (vmid < GUEST_VMID_START) {
		ERROR("invalid vmid %u\n", vmid);
		return res;
	}
	guest = __get_guest_by_kvm(&kvm, &i);
	if (guest != NULL) {
		guest_index[guest->vmid] = INVALID_GUEST;
		guest->vmid = vmid;
		guest_index[vmid] = i;
		guest->ctxt[0].vttbr_el2 = (((uint64_t)guest->EL1S2_pgd) | (vmid << 48));
		res = patrack_start(guest);
	}

	return res;
}

/**
 * Release guest stage 2 mappings.
 *
 * Unmap the whole guest stage 2 if the requested range covers the entire guest
 * RAM area. This function can be used to optimize guest reboot and shutdown
 * time. Function requires that all the guest RAM slots fit into the given IPA
 * range - return error if this is not the case and let the default logic to
 * handle the unmap request.
 *
 * @param guest the guest for which the stage 2 is released
 * @param rangestart unmap range start
 * @param rangeend unmap range end
 * @return zero on success or error code if unmap was not done
 */
static int release_guest_s2(kvm_guest_t *guest, uint64_t rangestart, uint64_t rangeend)
{
	int res;
	uint64_t slot_start = ~0UL, slot_end = ~0UL;
	kvm_memslots *slots = guest->slots;
	int i;

	if (rangestart >= rangeend)
		return -EINVAL;

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++) {
		if (!slots[i].slot.npages)
			continue;

		if (slots[i].slot.flags & KVM_MEM_READONLY)
			continue;

		slot_start = slots[i].region.guest_phys_addr;
		slot_end = slot_start + slots[i].region.memory_size;

		if ((slot_start < rangestart) || (slot_end > rangeend))
			return -ERANGE;
	}

	if (slot_start == ~0UL)
		return -ERANGE;

	memset(guest->hyp_page_data, 0, sizeof(guest->hyp_page_data));
	res = restore_host_mappings(guest);
	if (res)
		panic("restore_host_mappings failed with error %d\n", res);

	/* Trash pgd */
	res = free_pgd(&guest->s2_tablepool, NULL);
	if (res)
		panic("free_pgd failed\n");

	/* Get new one in to prepare for possible reboot */
	guest->EL1S2_pgd = alloc_pgd(guest, &guest->s2_tablepool);
	if (res)
		panic("alloc_pgd failed\n");

	guest->ctxt[0].vttbr_el2 = (((uint64_t)guest->EL1S2_pgd) |
				    ((uint64_t)guest->vmid << 48));

	/* Restart physical address tracking */
	res = patrack_stop(guest);
	if (res)
		panic("patrack stop failed with error %d\n", res);

	res = patrack_start(guest);
	if (res)
		panic("patrack start failed with error %d\n", res);

	guest->state = GUEST_STOPPED;

	return 0;
}

static int page_is_exec(uint64_t prot)
{
	switch (prot & S2_XN_MASK) {
	case S2_EXEC_EL1EL0:
	case S2_EXEC_EL0:
	case S2_EXEC_EL1:
		return 1;
	}
	return 0;
}

static int page_is_cacheable(uint64_t prot)
{
	uint64_t attr = prot & TYPE_MASK_STAGE2;
	return attr == S2_NORMAL_MEMORY;
}

int guest_map_range(kvm_guest_t *guest, uint64_t vaddr, uint64_t paddr,
		    uint64_t len, uint64_t prot)
{
	uint64_t page_vaddr, page_paddr, taddr, end, *pte;
	uint64_t newtype, maptype, mapprot, mc = 0;
	kvm_memslot *slot1;
	kvm_memslot *slot2;
	kvm_guest_t *host;
	int res;

	if (!guest || !vaddr || !paddr || (len % PAGE_SIZE)) {
		ERROR("invalid mapping request for guest %u: %p, %p, %lu\n",
		       guest->vmid, vaddr, paddr, len);
		res = -EINVAL;
		goto out_error;
	}

	if (guest->state > GUEST_RUNNING)
		return -EFAULT;

	host = get_guest(HOST_VMID);
	if (!host)
		panic("no host\n");

	/*
	 * Permission(s) are integrity verified, so always disable the
	 * dirty state
	 */
	bit_drop(prot, DBM_BIT);

	end = vaddr + len - 1;
	slot1 = gfn_to_memslot(guest, addr_to_fn(vaddr));
	slot2 = gfn_to_memslot(guest, addr_to_fn(end));
	if (!slot1 || (slot1 != slot2) || (slot1->flags & KVM_MEM_READONLY)) {
		ERROR("invalid memory slot %p, %p, %p\n",
		      slot1, slot2, slot1->flags);
		return -EINVAL;
	}
	newtype = (prot & TYPE_MASK_STAGE2);

	/*
	 * Do we know about this area?
	 */
	page_vaddr = vaddr;
	page_paddr = paddr;
	while (page_vaddr < (vaddr + len)) {
		pte = NULL;
		taddr = pt_walk(guest, STAGE2, page_vaddr, &pte);
		if (!pte || (taddr == ~0UL))
			goto new_map;
		/*
		 * Verify if the mapping already exists, ie. track identical
		 * existing mappings and skip the blocks already there.
		 */
		maptype = (*pte & TYPE_MASK_STAGE2);
		mapprot = (*pte & PROT_MASK_STAGE2);
		if ((taddr == page_paddr) && (maptype == newtype) &&
		    (mapprot == prot)) {
			mc++;
			goto cont;
		}
new_map:
		/*
		 * This is a new mapping; flush the data out prior to creating
		 * the mapping or changing its permissions. We don't want writes
		 * from the cache on something that changed permissions.
		 */
		if (page_is_cacheable(prot)) {
			if (page_is_exec(prot))
				__flush_icache_area((void *)page_paddr, PAGE_SIZE);
			else
				__flush_dcache_area((void *)page_paddr, PAGE_SIZE);
		}
		/*
		 * If it wasn't mapped and we are mapping it back, verify
		 * that the content is still the same. If the page was
		 * encrypted, decrypt it. If it's a new mapping, do nothing.
		 */
		res = decrypt_guest_page(guest, page_vaddr, page_paddr,
					 prot & PROT_MASK_STAGE2);
		if (res)
			goto out_error;
cont:
		page_vaddr += PAGE_SIZE;
		page_paddr += PAGE_SIZE;
	}
	/*
	 * If we had already mapped this area as per the request,
	 * this is probably smp related trap we already served. Don't
	 * hinder the guest progress by remapping again and doing
	 * the full break-before-make cycle.
	 */
	if (len == (mc * PAGE_SIZE))
		return 0;

	/*
	 * Attach the region to the guest
	 */
	res = mmap_range(guest, STAGE2, vaddr, paddr, len, prot,
			 KERNEL_MATTR);
	if (res)
		panic("mmap_range failed with error %d\n", res);

	/*
	 * Mark the region ownership
	 */
	res = patrack_mmap(guest, paddr, vaddr, len);
	if (res)
		panic("patrack_mmap failed with error %d\n", res);

	/*
	 * If it's a normal region that is mapped on the host, remove it.
	 * If it's a share, let it be but make sure the share area does
	 * not have execute permissions.
	 */
	if (is_share(guest, vaddr, len) == 1) {
		res = mmap_range(host, STAGE2, paddr, paddr, len,
				 (EL1S2_SH | PAGE_HYP_RW),
				 S2_NORMAL_MEMORY);
		if (res)
			panic("mmap_range failed with error %d\n", res);
	} else  {
		res = remove_host_range(guest, vaddr, len, false);
		if (res)
			panic("remove_host_range failed with error %d\n", res);
	}

out_error:
	return res;
}

int guest_unmap_range(kvm_guest_t *guest, uint64_t vaddr, uint64_t len, uint64_t sec)
{
	kvm_guest_t *host;
	uint64_t paddr, map_addr, range_end, pc = 0;
	uint64_t *pte;
	int res = 0;

	host = get_guest(HOST_VMID);
	if (!host)
		panic("no host\n");

	range_end = vaddr + len;
	if (!guest || (len % PAGE_SIZE) || (range_end < vaddr)) {
		ERROR("invalid unmap request for guest %u: %p, %lu\n",
		      guest->vmid, vaddr, len);
		res = -EINVAL;
		goto out_error;
	}

	if (range_end > guest->ramend)
		range_end = guest->ramend;

	switch (guest->state) {
	case GUEST_CRASHING:
		LOG("unmap on guest crash\n");
		return -EFAULT;
	case GUEST_STOPPED:
		/*
		 * Guest is stopped. Stage 2 will be released at
		 * free_guest.
		 */
		LOG("unmap while guest has stopped\n");
		return -EFAULT;
	case GUEST_RESET:
		/*
		 * Guest is in reset state. Release the whole stage 2
		 * range.
		 */
		LOG("unmap on guest reset\n");
		release_guest_s2(guest, 0, guest->ramend);
		return -EFAULT;
	default:
		/*
		 * Guest is still in running state. Check if we are about
		 * to release the whole guest IPA range. This may happen
		 * when the guest is killed and can't update its own power
		 * state.
		 */
		if (!sec && !release_guest_s2(guest, vaddr, range_end)) {
			LOG("unmap on guest kill\n");
			return -EFAULT;
		}
	}

	map_addr = vaddr;
	while (map_addr < range_end) {
		paddr = pt_walk(guest, STAGE2, map_addr, &pte);
		if (paddr == ~0UL)
			goto do_loop;

		if ((guest->state == GUEST_RUNNING) && sec) {
			/*
			 * This is a mmu notifier chain call and the
			 * blob may get swapped out and freed. Take
			 * a measurement or encrypt it, depending on
			 * where it's headed.
			 */
			if (*pte & S2AP_WRITE) {
				/* The page is writable or dirty */
				res = encrypt_guest_page(guest,
							 map_addr,
							 paddr,
							 *pte & PROT_MASK_STAGE2);
				if (res)
					panic("encrypt_guest_page returned %d\n",
					      res);
			} else {
				/* The page is read-only or clean */
				res = add_range_info(guest, map_addr,
						     paddr, PAGE_SIZE, 0,
						     *pte & PROT_MASK_STAGE2);
				if (res)
					ERROR("add_range_info(%u): %lx:%d\n",
					      guest->vmid, map_addr, res);
			}
		} else {
			memset((void *)paddr, 0, PAGE_SIZE);
			free_range_info(guest, map_addr);
		}
		/*
		 * We may have changed the page contents, flush the page just
		 * in case before changing the permissions.
		 */
		if (page_is_cacheable(*pte)) {
			if (page_is_exec(*pte))
				__flush_icache_area((void *)paddr, PAGE_SIZE);
			else
				__flush_dcache_area((void *)paddr, PAGE_SIZE);
		}
		/*
		 * Detach the page from the guest
		 */
		res = unmap_range(guest, STAGE2, map_addr, PAGE_SIZE);
		if (res)
			panic("unmap_range failed with %d\n", res);

		res = patrack_unmap(guest, paddr, PAGE_SIZE);
		if (res)
			panic("patrack_unmap failed with %d\n", res);
		/*
		 * Give it back to the host
		 */
		res = restore_host_range(host, paddr, PAGE_SIZE, true);
		if (res)
			panic("restore_host_range failed with %d\n", res);

		pc += 1;
do_loop:
		map_addr += PAGE_SIZE;
		if (pc >= GUEST_MAX_PAGES)
			ERROR("Unmap page counter overflow");
	}

out_error:
	return pc;
}

int free_guest(void *kvm)
{
	kvm_guest_t *guest = NULL;
	kvm_guest_t *host = NULL;
	int i, res, gi;

	if (!kvm)
		return -EINVAL;

	host = get_guest(HOST_VMID);
	if (!host)
		panic("no host\n");

	guest = __get_guest_by_kvm(&kvm, NULL);
	if (guest == NULL)
		return 0;

	if (guest->EL1S2_pgd == host->EL1S2_pgd)
		panic("not host pgd\n");

	if (guest->vmid == HOST_VMID)
		return 0;

	res = restore_host_mappings(guest);
	if (res)
		return res;

	res = patrack_stop(guest);
	if (res)
		panic("patrack_stop error: %d\n",res);

	free_pgd(&guest->s2_tablepool, NULL);
	free_pgd(&guest->el2_tablepool, host->EL2S1_pgd);
	/*
	 * Handle VMID zero as a special case since it is used
	 * for early init purposes and there may exist another
	 * KVM instance already with VMID zero (for which
	 * the VMID will be assigned before its first run).
	 */
	if (guest->vmid)
		guest_index[guest->vmid] = INVALID_GUEST;
	else {
		for (i = 0; i < last_guest_index; i++) {
			if ((guests[i].kvm != kvm) && guests[i].vmid == 0) {
				guest_index[0] = i;
				break;
			}
		}
	}

	guest->state = GUEST_INVALID;
	guest_mempool_free(guest);

	gi = guest->index;
	memset(guest, 0, sizeof(*guest));
	format_guest(gi);
	guest->vmid = INVALID_VMID;

	dsb();
	isb();

	return 0;
}

int delete_memslot(kvm_guest_t *guest, kvm_memslots *slots, short id)
{
	int i, ret = -ENOENT;
	uint64_t gpa, len, ramend;

	if (!slots[id].slot.npages) {
		ERROR("invalid slot\n");
		return ret;
	}

	gpa = slots[id].region.guest_phys_addr;
	len = slots[id].region.memory_size;
	ret = guest_unmap_range(guest, gpa, len, 0);
	if (ret < 0)
		return ret;

	memset(&slots[id].region, 0, sizeof(kvm_userspace_memory_region));
	memset(&slots[id].slot, 0, sizeof(kvm_memslot));

	/* Do we need to update ramend? */
	ramend = gpa + len;
	if (ramend < guest->ramend)
		return ret;

	guest->ramend = 0;
	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++) {
		if (!slots[i].slot.npages)
			continue;

		gpa = slots[i].region.guest_phys_addr;
		ramend = gpa + slots[i].region.memory_size;

		if (guest->ramend < ramend)
			guest->ramend = ramend;
	}

	return ret;
}

int update_memslot(void *kvm, kvm_memslot *slot,
		   kvm_userspace_memory_region *reg)
{
	kvm_guest_t *guest;
	uint64_t addr, size;
	uint64_t ramend;

	if (!kvm || !slot || !reg)
		return -EINVAL;

	kvm = kern_hyp_va(kvm);
	slot = kern_hyp_va(slot);
	reg = kern_hyp_va(reg);

	if (slot->npages > 0x100000) {
		ERROR("slot too large\n");
		return -EINVAL;
	}
	guest = get_guest_by_kvm(kvm);
	if (!guest)
		return 0;

	guest->state = GUEST_INIT;
	if (slot->id > KVM_MEM_SLOTS_NUM) {
		ERROR("too many guest slots?\n");
		return -EINVAL;
	}
	addr = fn_to_addr(slot->base_gfn);
	size = slot->npages * PAGE_SIZE;

	/* Check for delete */
	if (!size)
		return delete_memslot(guest, guest->slots, slot->id);

	/* Check dupes */
	if (is_range_valid(addr, size, &guest->slots[0]))
		return 0;

	memcpy(&guest->slots[slot->id].region, reg, sizeof(*reg));
	memcpy(&guest->slots[slot->id].slot, slot, sizeof(*slot));

	ramend = fn_to_addr(guest->slots[slot->id].slot.base_gfn);
	ramend += guest->slots[slot->id].slot.npages * PAGE_SIZE;

	if (guest->ramend < ramend)
		guest->ramend = ramend;

	LOG("guest 0x%lx slot 0x%lx - 0x%lx\n", kvm, addr, addr + size);

	dsb();
	isb();

	return 0;
}

int guest_user_copy(uint64_t dest, uint64_t src, uint64_t count)
{
	uint64_t ttbr0_el1 = (read_reg(TTBR0_EL1) & TTBR_BADDR_MASK);
	uint64_t ttbr1_el1 = (read_reg(TTBR1_EL1) & TTBR_BADDR_MASK);
	uint64_t usr_addr, dest_pgd, src_pgd;
	kvm_guest_t *guest = NULL;

	/* Check if we have such guest */
	guest = get_guest_by_s1pgd((struct ptable *)ttbr0_el1);
	if (guest == NULL)
		return -ENOENT;

	if (guest->vmid == HOST_VMID)
		return -ENOENT;

	/*
	 * Set the guest user address and page tables to use.
	 * ttbr1_el1 contain the host kernel view of the memory.
	 * ttbr0_el1 contain the guest user space view of the memory.
	 */
	if ((dest & KERNEL_MAP)) {
		usr_addr = src;
		dest_pgd = ttbr1_el1;
		src_pgd = ttbr0_el1;
	} else {
		usr_addr = dest;
		dest_pgd = ttbr0_el1;
		src_pgd = ttbr1_el1;
	}

	/* Check that the guest address is within qemu boundaries */
	if (!is_range_valid_uaddr(usr_addr, count, &guest->slots[0]))
		return -EINVAL;

	return user_copy(dest, src, count, dest_pgd, src_pgd);
}

int guest_stage2_access_flag(uint64_t operation, uint64_t vmid, uint64_t ipa,
			     uint64_t size)
{
	int res;
	kvm_guest_t *guest;
	uint64_t addr, *pte;

	res = 0;
	guest = NULL;
	addr = 0;
	pte = NULL;

	/* We only support page granularity at the moment */
	if ((size != PAGE_SIZE) && (size != 0)) {
		res = -EINVAL;
		goto out_no_entry;
	}
	guest = get_guest(vmid);
	if (guest == NULL) {
		res = -EINVAL;
		goto out_no_entry;
	}
	addr = pt_walk(guest, STAGE2, ipa, &pte);
	if (addr == ~0UL) {
		res = -ENOENT;
		goto out_no_entry;
	}
	switch (operation) {
	case HYP_MKYOUNG:
		bit_set(*pte, AF_BIT);
		break;
	case HYP_MKOLD:
		res = !!(*pte & bit_to_mask(AF_BIT));
		if (res)
			bit_drop(*pte, AF_BIT);
		break;
	case HYP_ISYOUNG:
		res = !!(*pte & bit_to_mask(AF_BIT));
		break;
	default:
		res = -ENOSYS;
		break;
	}

out_no_entry:
	return res;
}

int guest_validate_range(kvm_guest_t *guest, uint64_t addr, uint64_t paddr,
			 size_t len)
{
	kvm_guest_t *host, *powner;
	uint64_t tmp;
	int ret;

	if (!guest) {
		ERROR("no guest?\n");
		return -EINVAL;
	}
	/*
	 * Get clearance for the range from the platform implementation.
	 */
	if (!platform_range_permitted(paddr, len)) {
		ERROR("platform rejected mapping of %p, %u\n",
		      paddr, len);
		ret = -EPERM;
		goto out_error;
	}
	/*
	 * Verify that the range is within the guest boundary.
	 */
	ret = is_range_valid(addr, len, guest->slots);
	if (!ret) {
		ERROR("range %p/%u not within guest boundary\n",
		      paddr, len);
		ret = -EPERM;
		goto out_error;
	}

	/*
	 * Check that we actually own this area.
	 */
	host = get_guest(HOST_VMID);

	tmp = paddr;
	while (tmp < (paddr + len)) {
		powner = owner_of(tmp);
		if (powner == guest)
			goto cont;

		if (powner != host) {
			ERROR("vmid %u not a page owner for %p\n",
			      guest->vmid, paddr);
			return -EPERM;
		}
cont:
		tmp += PAGE_SIZE;
	}

	return 0;

out_error:
	ERROR("failed gpa:0x%lx hpa:0x%lx len:%d err:%d\n",
	       addr, paddr, len, ret);
	return ret;
}

int guest_vcpu_reg_reset(void *kvm, uint64_t vcpuid)
{
	kvm_guest_t *guest = __get_guest_by_kvm(&kvm, NULL);
	uint64_t mpidr;

	if (!guest) {
		LOG("bad kvm %p\n", kvm);
		return -ENOENT;
	}
	if (vcpuid >= NUM_VCPUS)
		return -EINVAL;
	guest->vcpu_ctxt[vcpuid].gpreg_sync_from_kvm = ~0;
	guest->vcpu_ctxt[vcpuid].pc_sync_from_kvm = PC_SYNC_COPY;
	mpidr = (vcpuid & 0x0f) << MPIDR_LEVEL_SHIFT(0);
	mpidr |= ((vcpuid >> 4) & 0xff) << MPIDR_LEVEL_SHIFT(1);
	mpidr |= ((vcpuid >> 12) & 0xff) << MPIDR_LEVEL_SHIFT(2);
	guest->vcpu_ctxt[vcpuid].state.mpidr_el1 = (1UL << 31) | mpidr;
	return 0;
}

#ifdef EXITLOG
static void guest_exitlog_add(kvm_guest_t *guest, uint32_t esr,
			      uint64_t exception_index)
{
	uint64_t idx;

	if (exception_index == ARM_EXCEPTION_IRQ) {
		guest->exitlog.interrupts++;
		return;
	}

	idx = ESR_EC(esr);
	guest->exitlog.exceptions[idx]++;

	switch (idx) {
	case 0x18:
		for (idx = 0; idx < SYSREG_TRAPLOGITEMS; idx++) {
			if (guest->exitlog.sysreg_traplog[idx].name == ISS_SYSREG_NAME(esr)) {
				if (ISS_SYSREG_DIR(esr))
					guest->exitlog.sysreg_traplog[idx].rcount++;
				else
					guest->exitlog.sysreg_traplog[idx].wcount++;
				break;
			}
			if (guest->exitlog.sysreg_traplog[idx].name == 0) {
				guest->exitlog.sysreg_traplog[idx].name = ISS_SYSREG_NAME(esr);
				break;
			}
		}
		if (idx >= SYSREG_TRAPLOGITEMS)
			ERROR("sysreg_traplog full\n");
		break;
	default:
		break;
	}
}
#else
static inline void guest_exitlog_add(kvm_guest_t *guest, uint32_t esr,
				     uint64_t exception_index)
{
}
#endif

/*
 * Note that this may bypass core_lock. This is acceptable as long as
 * we only access static guest data or VCPU registers which won't be
 * concurrently accessed by other cores.
 */
void guest_exit_prep(uint64_t vmid, uint64_t vcpuid, uint32_t esr,
		     struct user_pt_regs *regs, uint64_t exception_index)
{
	struct vcpu_context *ctxt;
	uint32_t reg;
	uint64_t ipa;
	kvm_memslot *slot;
	kvm_guest_t *guest = get_guest(vmid);

	if (!guest || vcpuid >= NUM_VCPUS) {
		ERROR("invalid vmid %u or vcpuid %u\n",
		      vmid, vcpuid);
		return;
	}
	ctxt = &guest->vcpu_ctxt[vcpuid];

	memcpy(&ctxt->regs.regs, &regs->regs, sizeof(ctxt->regs.regs));
	ctxt->regs.sp = read_reg(SP_EL0);
	ctxt->regs.pc = read_reg(ELR_EL2);
#ifndef GUESTDEBUG
	write_reg(ELR_EL2, 0);
#endif
	guest_exitlog_add(guest, esr, exception_index);

	switch (ESR_EC(esr)) {
	case 0x01:	/* WFx */
		ctxt->pc_sync_from_kvm = PC_SYNC_SKIP;
		break;
	case 0x16:	/* HVC */
		ctxt->kvm_regs->regs[0] = ctxt->regs.regs[0];
		ctxt->kvm_regs->regs[1] = ctxt->regs.regs[1];
		ctxt->kvm_regs->regs[2] = ctxt->regs.regs[2];
		ctxt->kvm_regs->regs[3] = ctxt->regs.regs[3];
		bit_set(ctxt->gpreg_sync_from_kvm, 0);
		break;
	case 0x18:	/* sysreg access */
		ctxt->pc_sync_from_kvm = PC_SYNC_SKIP;
		reg = ISS_SYSREG_RT(esr);
		if (reg == 31)
			break;
		if (ISS_SYSREG_DIR(esr))
			/* mrs -> write to gpr */
			bit_set(ctxt->gpreg_sync_from_kvm, reg);
		else
			/* msr -> read from gpr */
			ctxt->kvm_regs->regs[reg] = ctxt->regs.regs[reg];
		break;
	case 0x24:	/* data abort */
		if (!ISS_DABT_ISV(esr))
			break;
		ipa = read_reg(HPFAR_EL2) << 8;
		slot = gfn_to_memslot(guest, addr_to_fn(ipa));
		if (slot && !(slot->flags & KVM_MEM_READONLY))
			break;
		ctxt->pc_sync_from_kvm = PC_SYNC_SKIP;
		reg = ISS_DABT_SRT(esr);
		if (reg == 31)
			break;
		if (ISS_DABT_WNR(esr))
			/* write to memory -> read from gpr */
			ctxt->kvm_regs->regs[reg] = ctxt->regs.regs[reg];
		else
			/* read from memory -> write to gpr */
			bit_set(ctxt->gpreg_sync_from_kvm, reg);
		break;
	default:
		break;
	}

#ifdef GUESTDEBUG
	hyp_sync_gpregs(vmid, vcpuid);
	ctxt->kvm_regs->sp = read_reg(SP_EL0);
	ctxt->kvm_regs->pc = read_reg(ELR_EL2);
#endif
}

bool host_data_abort(uint64_t vmid, uint64_t ttbr0_el1, uint64_t far_el2, void *regs)
{
	kvm_guest_t *guest;
	uint64_t spsr_el2, elr_el2, paddr;
	bool res = false;

	if (vmid != HOST_VMID)
		panic("host_data_abort for non-host");

	spin_lock(&core_lock);

	paddr = (uint64_t)virt_to_ipa((void *)far_el2);
	/* Shared page should never abort at host context. */
	if (is_any_share(paddr))
		panic("host should not have shares\n");

	guest = get_guest_by_s1pgd((struct ptable *)(ttbr0_el1 &
				   TTBR_BADDR_MASK));
	spsr_el2 = read_reg(SPSR_EL2);
	elr_el2 = read_reg(ELR_EL2);

	if (guest && guest->state == GUEST_RESET) {
		/*
		 * We arrive here if guest is in reset state and host pages
		 * has not yet been restored. Make sure the faulting page
		 * belongs to this guest and map the page back to host.
		 */
		if (patrack(guest, paddr) == paddr) {
			memset((void *)paddr, 0, PAGE_SIZE);
			res = __map_back_host_page(get_guest(vmid), guest,
							     far_el2);
			if (res)
				goto out;
			ERROR("failed to restore %p (%p) to the host\n",
			      far_el2, paddr);
		}
	}

	ERROR("guest access violation for %p (%p), syndrome %p, pstate %p\n",
	      far_el2, paddr, read_reg(ESR_EL2), spsr_el2);
	ERROR("exception was at host virtual address %p (%p)\n",
	      elr_el2, virt_to_phys((void *)elr_el2));
	print_regs(regs);

	switch (spsr_el2 & 0xC) {
	case 0x0:
#ifdef GUESTDEBUG
		LOG("guest debug: access OK\n");
		res = __map_back_host_page(get_guest(vmid), guest, far_el2);
		break;
#endif
		if (guest)
			ERROR("appears to be vm manager access violation\n");
		else
			ERROR("appears to be unknown userspace process?\n");

		ERROR("requesting violating process core dump\n");
		res = do_process_core(guest, regs);
		break;
	case 0x4:
	case 0x5:
		ERROR("kernel violation: requesting host kernel crash dump\n");

		res = do_kernel_crash();
		break;
	case 0x8:
	case 0x9:
		panic("trapped el2 crash -- aborting\n");
		break;
	}
out:
	spin_unlock(&core_lock);

	return res;
}

int guest_cache_op(kvm_guest_t *guest, uint64_t addr, size_t len,
		   uint32_t type)
{
	uint64_t phys;
	int res = -ENOSYS;

	if (!guest || !addr || !len || (type > 2))
		return -EINVAL;

	phys = pt_walk(guest, STAGE2, addr, NULL);
	if (phys == ~0UL)
		return -ENOENT;

	switch (type) {
	case 0:
		__flush_dcache_area((void *)phys, len);
		res = 0;
		break;
	case 1:
		__flush_icache_area((void *)phys, len);
		res = 0;
		break;
	case 2:
		__inval_dcache_area((void *)phys, len);
		res = 0;
		break;
	default:
		res = -EINVAL;
		break;
	}

	return res;
}

int guest_region_protect(kvm_guest_t *guest, uint64_t addr, size_t len,
			 uint64_t prot)
{
	uint64_t phys, end, pval = 0, tval = 0;
	uint64_t *pte;
	int res;

	if (!guest || !addr || !len || (prot > 7))
		return -EINVAL;

	end = addr + len;
	while (addr < end) {
		phys = pt_walk(guest, STAGE2, addr, &pte);
		if (phys == ~0UL)
			goto cont;

		pval = *pte & PROT_MASK_STAGE2;
		tval = *pte & TYPE_MASK_STAGE2;

		/* Read */
		if (prot & 0x1)
			pval &= ~S2AP_READ;

		/* Write */
		if (prot & 0x2)
			pval &= ~S2AP_WRITE;

		/* Exec */
		if (prot & 0x4) {
			/* 53: 0, 54: 1 */
			bit_set(pval, S2_XN_SHIFT + 1);
			bit_drop(pval, S2_XN_SHIFT);
		}
		res = mmap_range(guest, STAGE2, addr, phys, PAGE_SIZE,
				 pval, tval);
		if (!res)
			panic("mmap_range returned %d\n", res);

cont:
		addr += PAGE_SIZE;
	}

	return 0;
}

void set_memory_readable(kvm_guest_t *guest)
{
	if (!guest)
		return;

	LOG("restoring pages for guest %u..\n", guest->vmid);
	restore_host_mappings(guest);
	dsb(); isb();
}

bool do_kernel_crash()
{
	int iival = UNDEFINED;
	uint64_t elr_el2;
	void *phys;

	elr_el2 = read_reg(ELR_EL2);
	phys = virt_to_ipa((void *)elr_el2);
	if (phys == (void *)~0UL)
		panic("");

	memcpy(phys, &iival, 4);
	write_reg(ELR_EL2, elr_el2);

	return true;
}

bool do_process_core(kvm_guest_t *guest, void *regs)
{
	int iival = UNDEFINED;
	uint64_t elr_el2;
	void *phys;

	/*
	 * Userspace abort, crash only the process at hand
	 */
	if (guest) {
		if (guest->state != GUEST_RUNNING)
			return false;
		guest->state = GUEST_CRASHING;
	}

	elr_el2 = read_reg(ELR_EL2);
	phys = virt_to_ipa((void *)elr_el2);
	if (phys == (void *)~0UL)
		panic("");

	if (guest) {
		/*
		 * Make the core dump region readable immediately, either as
		 * zeroes or data.
		 */
		set_memory_readable(guest);

		/*
		 * Save the instruction and address that failed
		 */
		memcpy(&guest->fail_inst, phys, 4);
		guest->fail_addr = phys;

	}
	/* Feed invalid instruction */
	memcpy(phys, &iival, 4);

	/* And return to it */
	write_reg(ELR_EL2, elr_el2);

	return true;
}
