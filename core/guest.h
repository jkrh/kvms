/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_GUEST_H__
#define __KVM_GUEST_H__

#include <stdint.h>
#include <errno.h>

#include "hvccall-defines.h"
#include "mm.h"
#include "host_defs.h"

#ifndef NUM_VCPUS
#define NUM_VCPUS 8
#endif
#ifndef MAX_GUESTS
#define MAX_GUESTS 8
#endif

#define KVM_USER_MEM_SLOTS 512
#define KVM_PRIVATE_MEM_SLOTS 0
#ifndef KVM_MEM_SLOTS_NUM
#define KVM_MEM_SLOTS_NUM (KVM_USER_MEM_SLOTS + KVM_PRIVATE_MEM_SLOTS)
#endif

typedef int kernel_func_t(uint64_t, ...);

typedef struct {
	uint64_t vttbr_el2;
	uint64_t vtcr_el2;
	uint64_t hcr_el2;
	uint64_t cptr_el2;
	uint64_t mdcr_el2;
	uint64_t hstr_el2;
} sys_context_t;

typedef enum {
	guest_invalid = 0x0,
	guest_stopped = 0x1,
	guest_running = 0x2,
	guest_sleeping = 0x3,
} guest_state_t;

typedef struct {
	uint32_t vmid;
	guest_state_t state;
	kernel_func_t *cpu_map[NUM_VCPUS];
	struct ptable *s1_pgd;
	struct ptable *s2_pgd;
	void *kvm;	/* struct kvm */
	kvm_memslots slots[KVM_MEM_SLOTS_NUM];
	kvm_page_data hyp_page_data[MAX_PAGING_BLOCKS];
	uint64_t pd_index;
	uint64_t ramend;
	uint32_t sn;
	uint32_t table_levels;
	sys_context_t ctxt[PLATFORM_CORE_COUNT];
} kvm_guest_t;

/**
 * Initialize the guests and guest lookup array.
 */
void init_guest_array(void);

/**
 * Initialize a new kvm guest. KVM structure must be allocated
 * and initialized by the kernel and mapped to the HYP realm.
 *
 * @param kvm pointer to the kernel allocated kvm struct
 * @return zero on success or negative error code on failure
 */
int init_guest(void *kvm);

/**
 * Free a existing kvm guest. KVM structure must not be freed
 * yet from the kernel.
 *
 * @param kvm pointer to the kernel allocated kvm struct
 * @return zero on success or negative error code on failure
 */
int free_guest(void *kvm);

/**
 * Update current guest state
 *
 * @param state, the new guest state
 * @return zero on success or negative error code on failure
 */
int update_guest_state(guest_state_t state);

/**
 * Update guest memory slots
 *
 * @param kvm the guest to update
 * @param slot kernel allocated kvm_memslot structure belonging to guest 'kvm'
 * @param mem kernel allocated memory region structure belonging to guest 'kvm'
 * @return zero on success or negative error code on failure
 */
int update_memslot(void *kvm, kvm_memslot *slot, kvm_userspace_memory_region *mem);

/**
 *  @param guest the guest to map to
 *  @param vaddr virtual address (ipa) to map
 *  @param paddr physical address to map to
 *  @param len length of the blob
 *  @param prot memory protection bits of the blob
 *  @param type type of memory
 *  @return zero on success or negative error code on failure
 */
int guest_map_range(kvm_guest_t *guest, uint64_t vaddr, uint64_t paddr,
		    uint64_t len, uint64_t prot);

/**
 *  @param guest the guest to unmap from
 *  @param addr virtual address (ipa) to unmap
 *  @param len length of the blob
 *  @param notify set to false if the unmap is final; true otherwise
 *  @return zero on success or error bitfield [0:16 0xF0F0 16:32 PC]
 */
int guest_unmap_range(kvm_guest_t *guest, uint64_t addr, uint64_t len,
		      bool notify);

/**
 * Fetch given guest running state.
 *
 * @param vmid of the guest
 * @return enum guest_t
 */
guest_state_t get_guest_state(uint64_t vmid);

/**
 * Allocate guest structure for a VMID
 *
 * @param vmid of the guest
 * @return kvm_guest_t
 */
kvm_guest_t *get_free_guest(uint64_t vmid);

/**
 * Fetch given guest structure
 *
 * @param vmid of the guest
 * @return kvm_guest_t
 */
kvm_guest_t *get_guest(uint64_t vmid);
kvm_guest_t *get_guest_by_kvm(void *kvm);
kvm_guest_t *get_guest_by_s1pgd(struct ptable *pgd);
kvm_guest_t *get_guest_by_s2pgd(struct ptable *pgd);

/**
 * Set VMID for a KVM
 *
 * @param kvm structure of the guest
 * @param vmid to be set for the guest
 * @return zero on success or negative error code on failure
 */
int guest_set_vmid(void *kvm, uint64_t vmid);

/**
 * Perform memory copy for the current guest
 *
 * @param dest destination to copy to
 * @param src source to copy from
 * @param count amount of bytes to copy
 * @return zero on success or negative error code on failure
 */
int guest_user_copy(uint64_t dest, uint64_t src, uint64_t count);

/**
 * Stage2 page table access flag (AF) software management functions
 *
 * @param operation set, clear and get for AF
 * @param vmid guest virtual machine identification
 * @param ipa guest physical address
 * @param size range size
 * @return operation specific return value, zero if descriptor is not found
 * 	   HYP_MKYOUNG zero
 * 	   HYP_MKOLD one if the operation was done, zero otherwise
 * 	   HYP_ISYOUNG state of the AF flag (1 young, 0 old)
 */
int guest_stage2_access_flag(uint64_t operation, uint64_t vmid, uint64_t ipa,
			     uint64_t size);

/**
 * Determine if the given guest is allowed to map the requested range
 *
 * @param guest the guest
 * @param addr the virtual or the intermediate physical start address
 * @param paddr the physical start address
 * @param len length of the range
 * @return 0 if valid, negative error code otherwise
 */
int guest_validate_range(kvm_guest_t *guest, uint64_t addr, uint64_t paddr,
			 size_t len);

/**
 * Load host stage2 context
 *
 * @return 0 if ok, negative error code otherwise
 */
int load_host_s2(void);

/**
 * Load guest stage2 context
 *
 * @param vmid the guest virtual machine identifier
 * @return 0 if ok, negative error code otherwise
 */
int load_guest_s2(uint64_t vmid);

#endif // __KVM_GUEST_H__
