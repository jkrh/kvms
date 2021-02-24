/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __MM_H__
#define __MM_H__

#include <stdint.h>
#include <string.h>

#include "commondefines.h"

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

#define MAX_KVM_HYP_REGIONS 64
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
	uint64_t phys_addr;
	uint64_t len;
	uint32_t vmid;
	uint8_t sha256[32];
} kvm_page_data;

#ifdef HOSTBLINDING
int blind_host(uint64_t ipa, uint64_t paddr, size_t len);
#else
static inline int blind_host(uint64_t ipa, uint64_t paddr, size_t len)
{
	return 0;
}
#endif

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
 * Copy count bytes of memory from src to dest by using specified
 * address mappings.
 *
 * @param dest destination virtual address
 * @param src source virtual address
 * @param count amount of bytes to copy
 * @param dest_pgd destination mappings to use
 * @param src_pgd source mappings to use
 * @return zero if copy was done, negative error code otherwise
 */
int user_copy(uint64_t dest, uint64_t src, uint64_t count, uint64_t dest_pgd,
	      uint64_t src_pgd);

int add_kvm_hyp_region(uint64_t vaddr, uint64_t paddr, uint64_t size);

int remove_kvm_hyp_region(uint64_t vaddr);

#endif
