/*
 * platform_api.h functions prototypes that
 * the platform implementation is expected to implement.
 * These functions are called by the core functionality.
 */

#ifndef __PLATFORM_API_H__
#define __PLATFORM_API_H__

#include <stdint.h>
#include <stdbool.h>

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
 * @return zero if succesfully initialized,
 * 	   other than zero in case of error.
 */
int machine_init(void);

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

#endif /* __PLATFORM_API_H__ */
