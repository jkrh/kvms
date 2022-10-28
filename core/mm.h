/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __MM_H__
#define __MM_H__

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "commondefines.h"
#include "spinlock.h"

/*
 * Address types:
 *
 *  gva - guest virtual address
 *  gpa - guest physical address
 *  gfn - guest frame number
 *  hva - host virtual address
 *  hpa - host physical address
 *  hfn - host frame number
 */
typedef uint64_t gfn_t;

#define fn_to_addr(x) (x * PAGE_SIZE)
#define addr_to_fn(x) (x / PAGE_SIZE)

#define KVM_MEM_LOG_DIRTY_PAGES (1UL << 0)
#define KVM_MEM_READONLY (1UL << 1)

typedef struct {
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t size;
} kvm_hyp_region;

typedef struct {
	uint32_t slot;
	uint32_t flags;
	uint64_t guest_phys_addr;
	uint64_t memory_size; /* bytes */
	uint64_t userspace_addr; /* start of the userspace allocated memory */
} kvm_userspace_memory_region;

typedef struct {
	gfn_t base_gfn;
	uint64_t npages;
	uint64_t *dirty_bitmap;
	uint64_t userspace_addr;
	uint32_t flags;
	short id;
} kvm_memslot;

typedef struct {
	kvm_userspace_memory_region region;
	kvm_memslot slot;
} kvm_memslots;

typedef struct {
	/*
	 * Umm; this is IPA for the KVM guests and kswapd stage1 kernel
	 * linear addess for the host.
	 */
	uint64_t phys_addr;
#ifdef TESTS
	uint64_t ttbr0_el1;
	uint64_t ttbr1_el1;
#endif
	uint64_t prot;
	uint32_t len;
	uint32_t vmid;
	uint32_t nonce;
	rwlock_t el;
	uint8_t sha256[32];
} kvm_page_data;

/**
 * Translate kernel memory address to hyp address
 *
 * @param p kernel address to translate
 * @return the hyp address
 */
void *kern_hyp_va(void *p);

/**
 * Get current cpu host data storage location
 *
 * @return the host data address
 */
void *get_kvm_host_data(void);

/**
 * Get current vcpu storage location
 *
 * @return the vcpu address
 */
void *get_vcpu_ptr(void);

/**
 * Determine if physical address addr is valid for given guest
 *
 * @param addr the address to query
 * @param len length of the mapping
 * @param slots guest memory slots
 * @return 1 if it is, 0 otherwise
 */
int is_range_valid(uint64_t addr, size_t len, kvm_memslots *slots);

/**
 * Determine if userspace address addr is valid for given guest
 *
 * @param addr the address to query
 * @param len length of the mapping
 * @param slots guest memory slots
 * @return 1 if it is, 0 otherwise
 */
int is_range_valid_uaddr(uint64_t addr, size_t len, kvm_memslots *slots);

/**
 * Translate a guest frame number to a memory slot
 *
 * @param g the kvm guest
 * @param gfn guest frame number
 * @return memslot pointer or NULL if none
 */
kvm_memslot *gfn_to_memslot(void *, gfn_t gfn);

/**
 * Set given guest 'g' frame 'gfn' as dirty
 *
 * @param guest, the guest
 * @param gfn, the guest frame number
 * @return void
 */
void set_guest_page_dirty(void *g, gfn_t gfn);

/**
 * Fetch a page integrity structure for guest. The returned structure will not
 * disappear from under you until free_guest() is called and the guest has been
 * terminated.
 *
 * @param guest, the guest
 * @param ipa, the guest ipa base address
 * @return pointer to the page integrity structure,
 *         NULL on error.
 */
kvm_page_data *get_range_info(void *guest, uint64_t ipa);

/**
 * Encrypt a given guest page and record the activity
 *
 * @param guest, the guest
 * @param ipa, the base address to add integrity information for
 * @param addr, the host physical address the data is on
 * @param prot, permission bits of the page
 * @return zero on success, negative errno on error
 */
int encrypt_guest_page(void *guest, uint64_t ipa, uint64_t addr, uint64_t prot);

/**
 * Decrypt a given guest page and record the activity
 *
 * @param guest, the guest
 * @param ipa, the base address to add integrity information for
 * @param addr, the host physical address the data is on
 * @param prot, permission bits of the page
 * @return zero on success, negative errno on error
 */
int decrypt_guest_page(void *guest, uint64_t ipa, uint64_t addr, uint64_t prot);

/**
 * Add page integrity structure for address
 *
 * @param guest, the guest
 * @param ipa, the base ipa to add integrity information for
 * @param addr, the host physical address the new data is on
 * @param len, length of the section
 * @param nonce, zero if the page is encrypted; nonzero otherwise
 * @param prot, permission bits of the page
 * @return zero on success, negative errno on error
 */
int add_range_info(void *guest, uint64_t ipa, uint64_t addr, uint64_t len,
		   uint32_t nonce, uint64_t prot);

/**
 * Free a page integrity structure
 *
 * @param guest, the guest
 * @param ipa, the ipa address to clear
 * @return void
 */
void free_range_info(void *guest, uint64_t ipa);

/**
 * Verify memory integrity for address
 *
 * @param ipa, the guest ipa this is supposed to be
 * @param addr, the host physical address the new data is on
 * @param len, length of the blob
 * @param prot, permission bits of the page
 * @return zero on integrity OK,
 *         -ENOENT on unknown page,
 *         -EINVAL on integrity failure
 *         -errno on generic error
 */
int verify_range(void *guest, uint64_t ipa, uint64_t addr, uint64_t len,
		 uint64_t prot);

/**
 * Remove given range mapping from the host
 *
 * @param guest, the target guest this range is migrated to.
 *               If the guest argument equals to the host the given range must
 *               be physically contiguous.
 * @param gpa, the guest ipa to remove.
 *               If the guest equals to the host the given gpa must be equal
 *               to the physical address.
 * @param len, length of the range
 * @param contiguous, set to true if the range is physically contiguous
 * @return zero on success or negative error code on failure
 */
int remove_host_range(void *guest, uint64_t gpa, size_t len, bool contiguous);

/**
 * Restore given range mapping back to the host
 *
 * @param guest, the target guest this range is currently mapped.
 *               If the guest equals to the host the given range must be
 *               physically contiguous.
 * @param gpa, ipa of the physical address to restore.
 *               If guest equals to the host the given gpa must be equal
 *               to the physical address.
 * @param len, length of the range
 * @param contiguous, set to true if the range is physically contiguous
 * @return zero on success or negative error code on failure
 */
int restore_host_range(void *guest, uint64_t gpa, uint64_t len, bool contiguous);

/*
 * Internal use only
 */
bool __map_back_host_page(void *host, void *guest, uint64_t far_el2);

#ifdef HOSTBLINDING
/**
 * Restore host mappings after blinded guest exit
 *
 * @param guest, the exiting guest
 * @return zero on success or negative error code on failure
 */
int restore_host_mappings(void *guest);

#else

static inline int restore_host_mappings(void *guest)
{
	return 0;
}

#endif // HOSTBLINDING

#ifdef DEBUG
static inline void clean_guest_page(void *addr)
{
}
#else
static inline void clean_guest_page(void *addr)
{
	memset((void *)addr, 0, PAGE_SIZE);
}
#endif

#endif // __MM_H__
