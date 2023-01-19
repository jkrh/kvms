/*
 * platform_api.h functions prototypes that
 * the platform implementation is expected to implement.
 * These functions are called by the core functionality.
 */

#ifndef __PLATFORM_API_H__
#define __PLATFORM_API_H__

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "guest.h"

typedef struct {
	uint64_t start;
	uint64_t end;
	uint64_t phys;
	uint64_t range_size;
	uint64_t type;
	uint64_t share;
	uint64_t perms;
} memmap;

struct memrange{
	uint64_t start;
	uint64_t end;
};

/**
 * machine_init - Initialize host platform.
 *
 * This function should, at minimum, generate initial
 * mapping tables to a point that 1: the EL2 code can run
 * MMU enabled (el2 translation table) and 2: the EL1 code
 * can run with virtualization enabled (stage 2 tables).
 *
 * At persent only 1:1 IPA->PHY mapping is supported for
 * host stage 2 memory mapping.
 *
 * @host: Virtual machine (kvm) structure for the host.
 * @return zero if succesfully initialized,
 *	   other than zero in case of error.
 */
int machine_init(kvm_guest_t *host);

/**
 * machine_init_ready - Return the host platform initialization status.
 *
 * This function gets called, for example, by the memory mapping
 * core logic to check if the initial memory map is being generated
 * by the platform and no need to enter to more complicated mapping
 * logic.
 *
 * @return true if initialization is ready, false otherwise.
 */
bool machine_init_ready(void);

/**
 * platform_init_host_pgd - Initialize host platform pgd.
 *
 * This function should populate the host mapping table (Page Global Directory)
 * base addresses for 1) the EL2 (stage1 only) mapping host->EL2S1_pgd and 2) the
 * stage 2 mapping for the host virtual machine mapping host->EL1S2_pgd.
 *
 * @host: Virtual machine (kvm) structure for the host.
 * @return zero if succesfully initialized,
 *	   other than zero in case of error.
 */
int platform_init_host_pgd(kvm_guest_t *host);

/**
 * platform_early_setup - Initial platform specific setup.
 */
void platform_early_setup(void);

/**
 * platform_mmu_prepare - Platform specific MMU preparation.
 *
 * Set up PGD registers, enable needed features and traps.
 * Make system ready for enabling MMU.
 */
void platform_mmu_prepare(void);

/**
 * platform_get_next_vmid - Get next valid VMID.
 *
 * Check the provided VMID candidate against
 * the possible list of reserved VMIDs.
 * The provided VMID will be returned unless
 * there is a conflict. In case of conflict
 * a next valid VMID without conflict is returned.
 *
 * @next_vmid: Current candidate for next VMID
 * @return next valid VMID
 */
uint32_t platform_get_next_vmid(uint32_t next_vmid);

/**
 * platform_console_init - Initialize debug output channel.
 *
 * Implement the needed logic under this function to get
 * your debug channel (fex. UART) ready for printing.
 *
 * DEBUG needs to be defined in order to get the traces
 * conveyed to this channel.
 */
void platform_console_init(void);

/**
 * platfrom_get_stack_ptr - Get a pointer to stack memory.
 *
 * This function gets called by the hyp core implementation
 * during (host) platform initialization. Stack pointer gets
 * initialized with the value returned by this function. Stack
 * memory is owned by the EL2 layer.
 *
 * @init_index: Stack memory table index
 * @return Stack pointer
 */
uint8_t *platfrom_get_stack_ptr(uint64_t init_index);

/**
 * platform_range_permitted - get permission to alter mapping for a range
 *
 * Deny physical ranges that you don't want anyone (running at EL1) to
 * be able to alter. This API gets called by HVC mapping APIs for checking
 * permission for the area.
 *
 * @param pstart the start address of the range
 * @param len length of the range
 * @return 1 if permitted, 0 otherwise
 */
int platform_range_permitted(uint64_t pstart, size_t len);

/**
 * platform_init_denyrange - initial ranges which are not allowed to be changed
 *
 * See platform_range_permitted
 */
void platform_init_denyrange(void);

/**
 * platform_add_denyrange - deny further mappings for the given range
 *
 * See platform_range_permitted
 *
 * @param pstart the start address of the range
 * @param len length of the range
 */
void platform_add_denyrange(uint64_t pstart, size_t len);

/**
 * platform_entropy - fetch entropy from the platform source
 *
 * @param entropy, empty buffer to fill with entropy
 * @param len, desired entropy length
 * @return 0 on success, nonzero otherwise
 */
int platform_entropy(uint8_t *entropy, size_t len);

/**
 * platform_init_guest - platform specific guest initialization
 *
 * @param vmid, empty buffer to fill with entropy
 * @return 0 on success, nonzero otherwise
 */
int platform_init_guest(uint32_t vmid);

/**
 * platform_allow_guest_smc - ask if it is allowed to forward smc
 *
 * @param cn smc call id
 * @param a1-a7 argument registers
 * @return 1 if smc can be forwarded, zero otherwise
 */
int platform_allow_guest_smc(register_t cn, register_t a1, register_t a2,
			     register_t a3, register_t a4, register_t a5,
			     register_t a6, register_t a7);

/**
 * platform_get_static_key -derivate a key from platform secrets
 *
 * @param key the address where derivated key will be stored
 * @param key_size key size in bytes
 * @param salt a pointer to salt for derivating
 * @param salt-size salt size in bytes
 * @return 0 on success, nonzero otherwise
 */
int platform_get_static_key(uint8_t *key, size_t key_size,
			      void *salt, size_t salt_size);
#endif /* __PLATFORM_API_H__ */
