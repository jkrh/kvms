#include <stdint.h>

/**
 * Count the amount of guest ram visible to the host
 *
 * @param vmid to query
 * @param lock make the pages read only for the guest
 * @return int count of shared pages or -errno
 */
int count_shared(uint32_t vmid, bool lock);

/**
 * Print memory mappings for given guest to console/log
 *
 * @param vmid vmid of the guest to dump
 * @param stage STAGE1 or STAGE2 of the address translation
 * @return total number of pages in the guest or -errno
 */
int print_mappings(uint32_t vmid, uint64_t stage);

/**
 * Print EL2 mode memory mappings to console/log
 *
 * @param void
 * @return total number of mapped pages or -errno
 */
int print_mappings_el2(void);

/**
 * Validate host mappings
 *
 * Run all kernel stage 1 and hyp generated stage 2 host mappings via
 * the software walk and via the mmu. The call will validate that the
 * MMU level view of the mappings agree with what ever is stated in
 * the page tables. The call will scan the kernel virtual memory
 * completely.
 *
 * This should validate:
 * - The TLB state
 * - The software walk logic to match that of the MMU
 * - QEMU softmmu when running on the emulation
 *
 * Besides these the call might detect potential page table corruptions.
 * https://lists.nongnu.org/archive/html/qemu-arm/2021-11/msg00227.html
 *
 * @param void
 * @return total number of mismatches or -errno
 */
int validate_host_mappings(void);

/*
 * Print a page table at address
 *
 * @param table table to dump
 * @return void
 */
void print_table(struct ptable *addr);

/**
 * Print page tables for given vmid to console/log
 *
 * @param vmid, vmid to dump
 * @return void
 */
void print_tables(uint64_t vmid);
