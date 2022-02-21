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

#include "platform_api.h"
#include "host_platform.h"
#include "hyp_config.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"
#include "mbedtls/platform.h"

extern struct mbedtls_entropy_context mbedtls_entropy_ctx;
extern uint64_t core_lock;

#define CHECKRES(x) if (x != MBEDTLS_EXIT_SUCCESS) return -EFAULT;
#define ARMV8_PMU_USERENR_MASK 0xf

extern struct mbedtls_ctr_drbg_context ctr_drbg;

struct hyp_extension_ops {
	int (*load_host_stage2)(void);
	int (*load_guest_stage2)(uint64_t vmid);
	void (*save_host_traps)(void);
	void (*restore_host_traps)(void);
	void *(*hyp_vcpu_regs)(uint64_t vmid, uint64_t vcpuid);
	uint64_t (*guest_enter)(void *vcpu);
};

/*
 * FIXME: calculate vmid offset
 * properly in asm_offsets.c
 */
#ifndef KVM_ARCH_VMID_OFFT
#define KVM_ARCH_VMID_OFFT 0
#endif

#define _KVM_GET_ARCH(x) ((char *)x + KVM_ARCH)
#define _KVM_GET_VMID(x) (_KVM_GET_ARCH((char *)x) + \
			  KVM_ARCH_VMID + KVM_ARCH_VMID_OFFT)

#define KVM_GET_VMID(x) (*(uint32_t *)_KVM_GET_VMID(x))
#define KVM_GET_PGD_PTR(x) ((uint64_t *)(_KVM_GET_ARCH((char *)x) + KVM_ARCH_PGD))
#define KVM_GET_EXT_OPS_PTR(x) ((struct hyp_extension_ops *)(_KVM_GET_ARCH((char *)x) + KVM_EXT_OPS))

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
#define ISS_DABT_ISV(esr)    (!!((esr) & 0x1000000))
#define ISS_DABT_SRT(esr)    (((esr) & 0x1f0000) >> 16)
#define ISS_DABT_WNR(esr)    (!!((esr) & 0x40))

static uint16_t guest_index[PRODUCT_VMID_MAX] ALIGN(16);
kvm_guest_t guests[MAX_VM] ALIGN(16);

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
	}
}

void init_guest_array(void)
{
	int i;

	for (i = 0; i < PRODUCT_VMID_MAX; i++)
		guest_index[i] = INVALID_GUEST;

	_zeromem16(guests, sizeof(guests));
	for (i = 0; i < MAX_VM; i++)
		format_guest(i);
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
		return ARM_EXCEPTION_HYP_GONE; /* 0xbadca11 */
	kvm_regs = VCPU_GET_REGS(vcpu);
	ctxt = &guest->vcpu_ctxt[vcpuid];
	ctxt->kvm_regs = kvm_regs;

	for (reg = 0; reg < 31; reg++)
		if (bit_raised(ctxt->gpreg_sync_from_kvm, reg))
			ctxt->regs.regs[reg] = kvm_regs->regs[reg];
	switch (ctxt->pc_sync_from_kvm) {
	case PC_SYNC_SKIP:
		if (kvm_regs->pc == 4)
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

kvm_guest_t *get_free_guest(uint64_t vmid)
{
	int i;

	if ((guest_index[vmid] != INVALID_GUEST) &&
	    (vmid != 0))
		return NULL;

	for (i = 0; i < MAX_VM; i++) {
		if (guests[i].vmid == INVALID_VMID) {
			guest_index[vmid] = i;
			guests[i].index = i;
			guests[i].vmid = vmid;
			return &guests[i];
		}
	}
	return NULL;
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
	for (i = 0; i < MAX_VM; i++) {
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
		ERROR("%s, wrong type!", __func__);

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
		ERROR("%s, check alignment!", __func__);

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
		ERROR("%s, check alignment!", __func__);

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
				ERROR("%s, unable to remove %lx, err %d\n",
				      __func__, paddr, err);
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
		if (guest == NULL)
			return -ENOSPC;
	}

	host = get_guest(HOST_VMID);
	if (!host)
		return -EINVAL;
	/*
	 * Walk through the provided range to verify it is contiguous
	 * and physically mapped by the calling host context. This will also
	 * ensure that the result of previous guest_validate_range call is
	 * valid since we are dealing with stage1 addresses in this function.
	 */
	s1_pgd = (struct ptable *)(read_reg(TTBR1_EL1) & TTBR_BADDR_MASK);
	tpaddr = paddr;
	if (!s1_range_physically_contiguous(host, s1_pgd, s1addr, &tpaddr, len))
		return -EINVAL;

	res = remove_host_range(host, paddr, len, true);
	if (!res) {
		chunk.start = paddr;
		chunk.size = len;
		chunk.type = GUEST_MEMCHUNK_FREE;
		res = __guest_memchunk_add(guest, &chunk);
		if (res < 0)
			return -ENOSPC;
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
		return -EINVAL;

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

int init_guest(void *kvm)
{
	kvm_guest_t *guest = NULL;
	struct hyp_extension_ops *eops;
	uint64_t *pgd;
	uint8_t key[32];
	int res;

	if (!kvm)
		return -EINVAL;

	guest = __get_guest_by_kvm(&kvm, NULL);
	if (guest == NULL) {
		guest = alloc_guest(kvm);
		if (guest == NULL)
			return -ENOSPC;
	}

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
	guest->table_levels_s2 = TABLE_LEVELS;

	guest->vmid = KVM_GET_VMID(kvm);
	guest->ctxt[0].vttbr_el2 = (((uint64_t)guest->EL1S2_pgd) |
				    ((uint64_t)guest->vmid << 48));
	eops = KVM_GET_EXT_OPS_PTR(kvm);
	eops->load_host_stage2 = load_host_s2;
	eops->load_guest_stage2 = load_guest_s2;
	eops->save_host_traps = save_host_traps;
	eops->restore_host_traps = restore_host_traps;
	eops->hyp_vcpu_regs = hyp_vcpu_regs;
	eops->guest_enter = guest_enter;

	/* Save the current VM process stage1 PGDs */
	guest->EL1S1_0_pgd = (struct ptable *)(read_reg(TTBR0_EL1) & TTBR_BADDR_MASK);
	guest->EL1S1_1_pgd = (struct ptable *)(read_reg(TTBR1_EL1) & TTBR_BADDR_MASK);
	/* FIXME: do proper detection */
	guest->table_levels_s1 = TABLE_LEVELS;

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
	for (i = 0; i < MAX_VM; i++) {
		if ((guests[i].vmid != HOST_VMID) &&
		    (guests[i].EL1S1_0_pgd == pgd))
			return &guests[i];
	}
	/* And if it wasn't any, the host..  */
	for (i = 0; i < MAX_VM; i++) {
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

int is_any_share(uint64_t gpa)
{
	int i = 0;

	while (i < MAX_VM) {
		if (!guests[i].vmid || (guests[i].vmid == INVALID_VMID))
			goto cont;

		if (guests[i].vmid < GUEST_VMID_START)
			goto cont;

		if (is_share(&guests[i], gpa, PAGE_SIZE) == 1)
			return 1;

cont:
		i++;
	}
	return 0;
}

kvm_guest_t *get_guest_by_s2pgd(struct ptable *pgd)
{
	kvm_guest_t *guest = NULL;
	int i;

	for (i = 0; i < MAX_VM; i++) {
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

	if (vmid < GUEST_VMID_START)
		return res;

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
 * times. Function requires the guest RAM to be contiguous IPA range - return
 * error if this is not the case and let the default logic to handle the unmap
 * request.
 *
 * @param guest the guest for which the stage 2 is released
 * @param rangestart unmap range start
 * @param rangeend unmap range end
 * @return zero on success or error code if unmap was not done
 */
static int release_guest_s2(kvm_guest_t *guest, uint64_t rangestart, uint64_t rangeend)
{
	int res;
	uint64_t ram_start = ~0UL, ram_end = ~0UL;
	kvm_memslots *slots = guest->slots;
	int i;

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++) {
		if (!slots[i].slot.npages)
			continue;

		if (slots[i].slot.flags & KVM_MEM_READONLY)
			continue;

		/*
		 * We can continue if RAM slots are in ascending order
		 * and contiguous.
		 */
		if (ram_start < ~0UL) {
			if (slots[i].region.guest_phys_addr != ram_end)
				return -ERANGE;

			ram_end = ram_end + slots[i].region.memory_size;

		} else {
			ram_start = slots[i].region.guest_phys_addr;
			ram_end = ram_start + slots[i].region.memory_size;
		}
	}

	if (ram_start == ~0UL)
		return -ERANGE;

	/*
	 * If the range does not cover the whole guest RAM we can not
	 * release the whole guest stage 2 map here.
	 */
	if ((rangestart > ram_start) || (rangeend < ram_end))
		return -ERANGE;

	memset(guest->hyp_page_data, 0, sizeof(guest->hyp_page_data));
	res = restore_host_mappings(guest);
	if (res)
		HYP_ABORT();

	/* Trash pgd */
	res = free_pgd(&guest->s2_tablepool, NULL);
	if (res)
		HYP_ABORT();

	/* Get new one in to prepare for possible reboot */
	guest->EL1S2_pgd = alloc_pgd(guest, &guest->s2_tablepool);
	if (res)
		HYP_ABORT();

	guest->ctxt[0].vttbr_el2 = (((uint64_t)guest->EL1S2_pgd) |
				    ((uint64_t)guest->vmid << 48));

	return 0;
}

static int page_is_exec(uint64_t prot)
{
	switch (prot & S2_XN_MASK) {
	case S2_EXEC_EL1EL0:
		return 1;
	case S2_EXEC_EL0:
		return 1;
	case S2_EXEC_EL1:
		return 1;
	}
	return 0;
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
		res = -EINVAL;
		goto out_error;
	}

	if (guest->state == GUEST_CRASHING)
		return -EFAULT;

	host = get_guest(HOST_VMID);
	if (!host)
		HYP_ABORT();

	/*
	 * Permission(s) are integrity verified, so always disable the
	 * dirty state
	 */
	bit_drop(prot, DBM_BIT);

	end = vaddr + len - 1;
	slot1 = gfn_to_memslot(guest, addr_to_fn(vaddr));
	slot2 = gfn_to_memslot(guest, addr_to_fn(end));
	if (!slot1 || (slot1 != slot2) || (slot1->flags & KVM_MEM_READONLY))
		return -EINVAL;

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
		if (page_is_exec(prot))
			__flush_icache_area((void *)page_paddr, PAGE_SIZE);
		else
			__flush_dcache_area((void *)page_paddr, PAGE_SIZE);
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
		HYP_ABORT();

	/*
	 * Mark the region ownership
	 */
	res = patrack_mmap(guest, paddr, vaddr, len);
	if (res)
		ERROR("%s patrack_mmap error %d\n", __func__, res);

	/*
	 * If it's a normal region that is mapped on the host, remove it.
	 * If it's a share, let it be but make sure the share area does
	 * not have execute permissions.
	 */
	if (is_share(guest, vaddr, len) == 1) {
		res = mmap_range(host, STAGE2, paddr, paddr, len,
				 ((SH_INN << 8) | PAGE_HYP_RW),
				 S2_NORMAL_MEMORY);
		if (res)
			 HYP_ABORT();
	} else  {
		res = remove_host_range(guest, vaddr, len, false);
		if (res)
			 HYP_ABORT();
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
		HYP_ABORT();

	range_end = vaddr + len;
	if (!guest || (len % PAGE_SIZE) || (range_end < vaddr)) {
		res = -EINVAL;
		goto out_error;
	}

	if (guest->state == GUEST_CRASHING)
		return -EFAULT;

	if (range_end > guest->ramend)
		range_end = guest->ramend;

	if (!sec && !release_guest_s2(guest, vaddr, range_end))
		return 0;

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
					HYP_ABORT();
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
		if (page_is_exec(*pte))
			__flush_icache_area((void *)paddr, PAGE_SIZE);
		else
			__flush_dcache_area((void *)paddr, PAGE_SIZE);

		/*
		 * Detach the page from the guest
		 */
		res = unmap_range(guest, STAGE2, map_addr, PAGE_SIZE);
		if (res)
			HYP_ABORT();

		res = patrack_unmap(guest, paddr, PAGE_SIZE);
		if (res)
			ERROR("%s patrack_unmap error %d\n", __func__, res);

		/*
		 * Give it back to the host
		 */
		res = restore_host_range(host, paddr, PAGE_SIZE, true);
		if (res)
			HYP_ABORT();

		pc += 1;
do_loop:
		map_addr += PAGE_SIZE;
		if (pc >= GUEST_MAX_PAGES)
			ERROR("Unmap page counter overflow");
	}

out_error:
	/*
	 * Log on how many pages were actually unmapped if there is a mismatch
	 * in between the requested and actual number of pages.
	 */
	if ((len/PAGE_SIZE) != pc)
		LOG("guest %p (%u) %s request %p, %ld pages. Actual: %ld sec:%ld\n",
		    guest, guest->vmid, __func__, vaddr, (len/PAGE_SIZE), pc, sec);

	return res;
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
		HYP_ABORT();

	guest = __get_guest_by_kvm(&kvm, NULL);
	if (guest == NULL)
		return 0;

	if (guest->EL1S2_pgd == host->EL1S2_pgd)
		HYP_ABORT();

	if (guest->vmid == HOST_VMID)
		return 0;

	res = restore_host_mappings(guest);
	if (res)
		return res;

	res = patrack_stop(guest);
	if (res)
		ERROR("%s patrack_stop error: %d\n", __func__, res);

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
		for (i = 0; i < MAX_VM; i++) {
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

	if (slot->npages > 0x100000)
		return -EINVAL;

	guest = get_guest_by_kvm(kvm);
	if (!guest)
		return 0;

	if (guest->sn > KVM_MEM_SLOTS_NUM)
		return -EINVAL;

	addr = fn_to_addr(slot->base_gfn);
	size = slot->npages * PAGE_SIZE;

	/* Check dupes */
	if (is_range_valid(addr, size, &guest->slots[0]))
		return 0;

	memcpy(&guest->slots[guest->sn].region, reg, sizeof(*reg));
	memcpy(&guest->slots[guest->sn].slot, slot, sizeof(*slot));

	ramend = fn_to_addr(guest->slots[guest->sn].slot.base_gfn);
	ramend += guest->slots[guest->sn].slot.npages * PAGE_SIZE;

	if (guest->ramend < ramend)
		guest->ramend = ramend;

	LOG("guest 0x%lx slot 0x%lx - 0x%lx\n", kvm, addr, addr + size);
	guest->sn++;

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
	if ((size != PAGE_SIZE) && (size != 0))
		goto out_no_entry;

	guest = get_guest(vmid);
	if (guest == NULL)
		goto out_no_entry;

	addr = pt_walk(guest, STAGE2, ipa, &pte);

	if (addr == ~0UL)
		goto out_no_entry;

	switch (operation) {
	case HYP_MKYOUNG:
		bit_set(*pte, AF_BIT);
		break;
	case HYP_MKOLD:
		res = !!(*pte & bit_to_mask(AF_BIT));
		if (res) {
			bit_drop(*pte, AF_BIT);
		}
		break;
	case HYP_ISYOUNG:
		res = !!(*pte & bit_to_mask(AF_BIT));
		break;
	default:
		HYP_ABORT();
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

	if (!guest)
		return -EINVAL;

	/*
	 * Get clearance for the range from the platform implementation.
	 */
	if (!platform_range_permitted(paddr, len)) {
		ret = -EPERM;
		goto out_error;
	}
	/*
	 * Verify that the range is within the guest boundary.
	 */
	ret = is_range_valid(addr, len, guest->slots);
	if (!ret) {
		ret = -EPERM;
		goto out_error;
	}

	/*
	 * Check that we actually own this area.
	 */
	host = get_guest(HOST_VMID);

	tmp = paddr;
	while (tmp < (paddr + len)) {
		powner = owner_of(paddr);
		if (powner == guest)
			goto cont;

		if (powner && (powner != host))
			return -EPERM;

		/* Keep shares as 1:1 communication pipes */
		if (is_any_share(paddr))
			return -EPERM;
cont:
		tmp += PAGE_SIZE;
	}

	return 0;

out_error:
	ERROR("%s failed gpa:0x%lx hpa:0x%lx len:%d err:%d\n",
	       __func__, addr, paddr, len, ret);
	return ret;
}

int guest_vcpu_reg_reset(void *kvm, uint64_t vcpuid)
{
	kvm_guest_t *guest = __get_guest_by_kvm(&kvm, NULL);

	if (!guest) {
		LOG("%s: bad kvm %p\n", __func__, kvm);
		return -ENOENT;
	}
	if (vcpuid >= NUM_VCPUS)
		return -EINVAL;
	guest->vcpu_ctxt[vcpuid].gpreg_sync_from_kvm = ~0;
	guest->vcpu_ctxt[vcpuid].pc_sync_from_kvm = PC_SYNC_COPY;
	return 0;
}

/*
 * Note that this may bypass core_lock. This is acceptable as long as
 * we only access static guest data or VCPU registers which won't be
 * concurrently accessed by other cores.
 */
void guest_exit_prep(uint64_t vmid, uint64_t vcpuid, uint32_t esr, struct user_pt_regs *regs)
{
	struct vcpu_context *ctxt;
	uint32_t reg;
	uint64_t ipa;
	kvm_memslot *slot;
	kvm_guest_t *guest = get_guest(vmid);

	if (!guest || vcpuid >= NUM_VCPUS) {
		ERROR("%s: invalid vmid %u or vcpuid %u\n",
		      __func__,  vmid, vcpuid);
		return;
	}
	ctxt = &guest->vcpu_ctxt[vcpuid];

	memcpy(&ctxt->regs.regs, &regs->regs, sizeof(ctxt->regs.regs));
	ctxt->regs.sp = read_reg(SP_EL0);
	ctxt->regs.pc = read_reg(ELR_EL2);
	write_reg(ELR_EL2, 0);

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
}

bool host_data_abort(uint64_t vmid, uint64_t ttbr0_el1, uint64_t far_el2, void *regs)
{
	kvm_guest_t *guest;
	uint64_t spsr_el2;
	bool res = false;

	guest = get_guest_by_s1pgd((struct ptable *)(ttbr0_el1 &
				   TTBR_BADDR_MASK));
	if (!guest)
		return res;

	spin_lock(&core_lock);
	spsr_el2 = read_reg(SPSR_EL2);
	switch(spsr_el2 & 0xF) {
	case 0x0:
		res = do_process_core(guest, regs);
		break;
	case 0x4:
	case 0x5:
		ERROR("%s: please fix qemu guest access at %p\n", __func__,
		      far_el2);
		res = __map_back_host_page(get_guest(vmid), guest, far_el2);
		break;
	}
	spin_unlock(&core_lock);

	return res;
}

void set_memory_readable(kvm_guest_t *guest)
{
	if (!guest)
		return;

	LOG("Restoring pages for guest %u..\n", guest->vmid);
	restore_host_mappings(guest);
	dsb(); isb();
}

bool do_process_core(kvm_guest_t *guest, void *regs)
{
	int iival = UNDEFINED;
	uint64_t elr_el2;
	void *phys;

	if (guest->state != GUEST_RUNNING)
		return false;
	guest->state = GUEST_CRASHING;

	/*
	 * Userspace abort, crash only the process at hand
	 */
	elr_el2 = read_reg(ELR_EL2);
	ERROR("Userspace data abort at host virtual address %p(%p)\n",
	   (void *)elr_el2, virt_to_phys((void *)elr_el2));
	ERROR("Failing address was %p\n", read_reg(FAR_EL2));
	print_regs(regs);

	phys = virt_to_ipa((void *)elr_el2);
	if (phys == (void *)~0UL)
		HYP_ABORT();

	/*
	 * Make the core dump region readable immediately, either
	 * as zeroes or data.
	 */
	set_memory_readable(guest);

	/* Grab the instruction that failed */
	guest->fail_addr = phys;
	memcpy(&guest->fail_inst, phys, 4);

	/* Feed invalid instruction */
	memcpy(phys, &iival, 4);

	/* And return to it */
	write_reg(ELR_EL2, elr_el2);

	return true;
}
