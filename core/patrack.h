/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Physical address tracker
 *
 * Main usage for physical address tracker is to keep track of actual host
 * physical addresses belonging to a guest. Addresses are mapped by using
 * stage 1 page table format thus enabling usage of ARM MMU utilities to make
 * fast searches for physical addresses whether or not they are mapped to the
 * guest. Host physical address mapping leverages the guest stage 2 table in
 * the following way:
 * hpa (tracker stage 1 map) -> gpa (guest stage 2 map) -> hpa
 *
 * Another usage of the physical address tracker is to keep track of the guest
 * physical addresses that are accessible from both the host and the guest.
 * Share mapping is implemented by leveraging the same stage 1 map as physical
 * address tracking but mapping the guest physical addresses with offset
 * PATRACK_SHAREOFFT as follows:
 * gpa + offt (tracker stage 1 map) -> gpa (guest stage 2 map) -> hpa
 */

#ifndef __PATRACK_H__
#define __PATRACK_H__

#include "sys_context.h"
#include "guest.h"

/*
 * PATRACK_TABLEOFFT
 * Physical address tracker page table offset is used to lift the tracker page
 * table intermediate physical addresses (IPAs) above the guest IPAs.
 * This enable using the same stage 2 table for both the tracker and the guest.
 * Note that in practise this offset sets maximum size for the guest:
 * For example value 0x2000000000 sets guest maximum size limit to 128Gib
 * (gigabytes). The same offsets (page table mapping) is mirrored at EL2
 * limiting the value 0x2000000000 usage for max 128Gib hosts.
 *
 * Adjust this value according to the required host actual physical address
 * size and guest physical address size by setting PLATFORM_PATRACK_TABLEOFFT
 * in platform implementation.
 */
#ifndef PLATFORM_PATRACK_TABLEOFFT
#define PLATFORM_PATRACK_TABLEOFFT	0x2000000000UL
#endif // PLATFORM_PATRACK_TABLEOFFT
#define PATRACK_TABLEOFFT		PLATFORM_PATRACK_TABLEOFFT
/*
 * PATRACK_SHAREOFFT
 * Physical address tracker share offset is used to keep track of guest
 * physical addresses which are accessible from both the guest and the host.
 * The same stage 1 tracking table which is used to keep track of the host
 * physical addresses mapped to guest is leveraged by mapping the shared guest
 * physical address on the physical address tracker share offset.
 *
 * Adjust this value according to the platform host actual physical address
 * size by setting PLATFORM_PATRACK_SHAREOFFT in platform implementation.
 * This value must be adjusted above the biggest possible host physical address
 * which can be assigned to guest.
 */
#ifndef PLATFORM_PATRACK_SHAREOFFT
#define PLATFORM_PATRACK_SHAREOFFT	0x4000000000UL
#endif // PLATFORM_PATRACK_SHAREOFFT
#define PATRACK_SHAREOFFT		PLATFORM_PATRACK_SHAREOFFT
/*
 * PATRACK_HPA_MULTIREF
 * Stage 1 table descriptor bit 63 (IGNORED by ARM specification) is used to
 * track the physical addresses which are mapped by more than one intermediate
 * physical address.
 */
#define PATRACK_HPA_MULTIREF	0x8000000000000000UL

struct patrack_hparef_s {
	uint64_t hpa;
	int count;
};

struct patrack_s {
	struct ptable *EL1S1_0_pgd;
	struct tablepool trailpool;
	sys_context_t ctxt;
};

/*
 * Start host physical address tracker for a guest.
 *
 * @param guest to start the tracker for
 * @return zero on success or error code on failure.
 */
int patrack_start(struct kvm_guest *guest);

/*
 * Stop the host physical address tracker for a guest.
 *
 * @param guest to stop the tracker for
 * @return zero on success or error code on failure.
 */
int patrack_stop(struct kvm_guest *guest);

/*
 * Map address range to tracker.
 *
 * @param guest to map the tracking range for
 * @param s1_addr for the range
 * @param ipa for the range
 * @param length for the range
 * @return zero on success or error code on failure.
 */
int patrack_mmap(struct kvm_guest *guest, uint64_t s1_addr, uint64_t ipa,
		 uint64_t length);

/*
 * Unmap address range from tracker.
 *
 * @param guest to unmap the tracking range from
 * @param s1_addr for the range
 * @param length for the range
 * @return zero on success or error code on failure.
 */
int patrack_unmap(struct kvm_guest *guest, uint64_t s1_addr, size_t length);

/*
 * Physical address tracker address validation.
 *
 * This function will:
 * 1. Check if physical address is mapped by the host
 * 2. If the address was not mapped by the host check if it
 *    is already mapped to the given guest.
 * 3. Deny access if the address was not mapped to the host or the guest.
 *
 * @param host
 * @param guest for which the address is validated for
 * @param hpa to validate
 * @return zero if hpa is mapped by the host,
 *         -EEXIST if address was not found from the host but was found from
 *         the guest.
 *         -EPERM if the address was not found.
 */
int patrack_validate_hpa(struct kvm_guest *host, struct kvm_guest *guest,
			 uint64_t hpa);

/*
 * Get the guest physical address (gpa) which maps the given host physical
 * address (hpa)
 *
 * @param guest to get the mapping from
 * @param hpa to get the gpa for
 * @return zero on success or error code on failure.
 */
uint64_t patrack_hpa2gpa(struct kvm_guest *guest, uint64_t hpa);

/*
 * Check if page table region is for tracker and adjust the IPA offset
 * accordingly.
 *
 * @param tpool currenty active table pool
 * @param table address to be adjusted
 * @return adjusted table address if this was a table address for physical
 *         address tracker. Unaltered table address otherwise.
 */
struct ptable *patrack_set_table_offt(struct tablepool *tpool,
				      struct ptable *table);

/*
 * Set guest physical address range share mapping.
 *
 * @param guest to set the share mapping
 * @param gpa share range start address
 * @param length for the share range
 * @return zero on success or error code on failure.
 */
int patrack_gpa_set_share(struct kvm_guest *guest, uint64_t gpa,
			  size_t length);

/*
 * Clear guest physical address share mapping.
 *
 * @param guest to clear the share mapping
 * @param gpa share range start address
 * @param length for the share range
 * @return zero on success or error code on failure.
 */
int patrack_gpa_clear_share(struct kvm_guest *guest, uint64_t gpa,
			    size_t length);

/*
 * Get information whether the guest physical address range is shared.
 *
 * @param guest to get the share information
 * @param gpa range start address
 * @param length for the range
 * @return zero if one or more pages within the range are not shared.
 *         one if all pages within the range are shared.
 */
int patrack_gpa_is_share(struct kvm_guest *guest, uint64_t gpa, size_t length);

/*
 * Check who owns a page
 *
 * @param addr physical memory address
 * @return owning VM pointer or NULL
 */
struct kvm_guest *owner_of(uint64_t addr);

#endif // __PATRACK_H__
