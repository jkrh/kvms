#include <stdint.h>

/**
 * Stop the execution for analysis
 *
 * Stop the hypervisor and the kernel execution for state inspection.
 * The kernel will stop on the next call to schedule().
 *
 * @return 0
 */
int debugstop(void);

/**
 * Restore the execution after analysis, see above
 *
 * @return 0
 */
int debugstart(void);

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
 * Print one address mapping for given guest to console/log
 *
 * @param vmid vmid of the guest to dump
 * @param stage STAGE1 or STAGE2 of the address translation
 * @param addr address to print mapping for
 * @return 1 if mapping found 0 otherwise
 */
int print_addr(uint32_t vmid, uint64_t stage, uint64_t addr);

/**
 * Attempt to translate one virtual address with 2 stage at translation command
 *
 * @param vaddr address to translate
 * @return the physical address if translation was successfull ~0UL otherwise
 */
uint64_t translate_addr(uint64_t vaddr);

/**
 * Print EL2 mode memory mappings to console/log
 *
 * @param void
 * @return total number of mapped pages or -errno
 */
int print_mappings_el2(void);

/**
 * Print shared areas to console/log
 *
 * @param vmid to dump
 * @return total number of mapped shares or -errno
 */
int print_shares(uint32_t vmid);

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
