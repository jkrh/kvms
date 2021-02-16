/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_GUEST_H__
#define __KVM_GUEST_H__

#include <stdint.h>
#include <errno.h>

#include "hvccall-defines.h"
#include "host_platform.h"
#include "mm.h"

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

#ifndef MAX_PAGING_BLOCKS
#define MAX_PAGING_BLOCKS 131072
#endif

#define GUEST_TABLE_LEVELS 4

typedef int kernel_func_t(uint64_t, ...);

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
	uint32_t sn;
	uint32_t table_levels;
} kvm_guest_t;

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
 * Fetch given guest running state.
 *
 * @param vmid of the guest
 * @return enum guest_t
 */
guest_state_t get_guest_state(uint64_t vmid);

/**
 * Fetch a page integrity structure for guest
 *
 * @param guest, the guest
 * @param ipa, the guest ipa
 * @return pointer to the page integrity structure,
 *         NULL on error.
 */
kvm_page_data *get_page_info(kvm_guest_t *guest, uint64_t ipa);

/**
 * Add page integrity structure for address
 *
 * @param guest, the guest
 * @param ipa, the guest ipa
 * @param addr, the host physical address
 * @return zero on success, negative errno on error
 */
int add_page_info(kvm_guest_t *guest, uint64_t ipa, uint64_t addr);

/**
 * Free a page integrity structure
 *
 * @param ipa, the guest ipa
 * @return void
 */
void free_page_info(kvm_guest_t *guest, uint64_t ipa);

/**
 * Verify page integrity for address
 *
 * @param ipa, the guest ipa
 * @param addr, the host physical address the new data is on
 * @return zero on integrity OK,
 *         -ENOENT on unknown page,
 *         -EINVAL on integrity failure
 *         -errno on generic error
 */
int verify_page(kvm_guest_t *guest, uint64_t ipa, uint64_t addr);

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
 * Perform memory copy for the current guest
 *
 * @param dest destination to copy to
 * @param src source to copy from
 * @param count amount of bytes to copy
 * @return zero on success or negative error code on failure
 */
int guest_user_copy(uint64_t dest, uint64_t src, uint64_t count);

/**
 * Restore host mappings after blinded guest exit
 *
 * @param guest, the exiting guest
 * @return zero on success or negative error code on failure
 */
#ifdef HOSTBLINDING
int restore_host_mappings(kvm_guest_t *guest);

/**
 * Restore given page back to the host.
 *
 * @param vaddr virtual address of the page
 * @param paddr physical address of the page
 * @return zero on success or negative error code on failure
 */
int restore_blinded_page(uint64_t vaddr, uint64_t paddr);
#else
static inline int restore_host_mappings(kvm_guest_t *guest)
{
	return 0;
}
static inline int restore_blinded_page(uint64_t vaddr, uint64_t paddr)
{
	return 0;
}
#endif // HOSTBLINDING

#endif // __KVM_GUEST_H__
