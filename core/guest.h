/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __KVM_GUEST_H__
#define __KVM_GUEST_H__

#include <stdint.h>
#include <errno.h>

#include "hvccall-defines.h"
#include "mm.h"
#include "host_defs.h"
#include "tables.h"
#include "pt_regs.h"
#include "sys_context.h"
#include "patrack.h"
#include "spinlock.h"

#include "mbedtls/aes.h"

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

#define INVALID_VMID    PRODUCT_VMID_MAX

typedef int kernel_func_t(uint64_t, ...);

typedef enum {
	GUEST_INVALID = 0x0,
	GUEST_INIT,
	GUEST_RUNNING,
	GUEST_STOPPED,
	GUEST_SLEEPING,
	GUEST_CRASHING,
	GUEST_RESET,
} guest_state_t;

enum pc_sync {
	PC_SYNC_NONE = 0,
	PC_SYNC_SKIP = 1,
	PC_SYNC_COPY = 2,
};

struct nvhe_sysregs {
	uint64_t mpidr_el1;
	uint64_t csselr_el1;
	uint64_t cpacr_el1;
	uint64_t ttbr0_el1;
	uint64_t ttbr1_el1;
	uint64_t tcr_el1;
	uint64_t esr_el1;
	uint64_t afsr0_el1;
	uint64_t afsr1_el1;
	uint64_t far_el1;
	uint64_t mair_el1;
	uint64_t vbar_el1;
	uint64_t contextidr_el1;
	uint64_t amair_el1;
	uint64_t cntkctl_el1;
	uint64_t par_el1;
	uint64_t tpidr_el1;
	uint64_t sp_el1;
	uint64_t elr_el1;
	uint64_t spsr_el1;
	uint64_t mdscr_el1;
	uint64_t tpidr_el0;
	uint64_t tpidrro_el0;
};

struct vcpu_context {
	struct user_pt_regs regs;
	struct user_pt_regs *kvm_regs;
	uint32_t gpreg_sync_from_kvm;
	enum pc_sync pc_sync_from_kvm;
	struct nvhe_sysregs state;
};

#ifdef EXITLOG
#define NUM_EC 64
#define SYSREG_TRAPLOGITEMS 128
struct sysreg_traplogitem {
	uint32_t name;
	uint64_t rcount;
	uint64_t wcount;
};
struct guest_exitlog {
	uint64_t exceptions[NUM_EC];
	uint64_t interrupts;
	struct sysreg_traplogitem sysreg_traplog[SYSREG_TRAPLOGITEMS];
};
#endif /* EXITLOG */

#define MIN_UNIQUE_ID_LEN 8
#define GUEST_UNIQUE_ID_LEN 32

struct kvm_guest {
	uint32_t vmid;
	guest_state_t state;
	kernel_func_t *cpu_map[NUM_VCPUS];
	struct ptable *EL1S1_0_pgd; /* ttbr0_el1 */
	struct ptable *EL1S1_1_pgd; /* ttbr1_el1 */
	struct ptable *EL1S2_pgd;   /* vttbr_el2 */
	struct ptable *EL2S1_pgd;   /* ttbr0_el2 */
	struct tablepool el2_tablepool;
	struct tablepool s2_tablepool;
	void *kvm;	/* struct kvm */
	kvm_memslots slots[KVM_MEM_SLOTS_NUM];
	spinlock_t page_data_lock;
	kvm_page_data *hyp_page_data[MAX_PAGING_BLOCKS];
	uint64_t pd_index;
	uint64_t ramend;
	uint8_t table_levels_el2s1;
	uint8_t table_levels_el1s1;
	uint8_t table_levels_el1s2;
	uint16_t index;
	sys_context_t ctxt[PLATFORM_CORE_COUNT];
	guest_memchunk_t mempool[GUEST_MEMCHUNKS_MAX];
	mbedtls_aes_context aes_ctx;
	struct patrack_s patrack;
	bool s2_host_access;
	struct vcpu_context vcpu_ctxt[NUM_VCPUS];
	void *fail_addr;
	uint32_t fail_inst;
	void *keybuf;
	uint8_t unique_id[GUEST_UNIQUE_ID_LEN];
#ifdef EXITLOG
	struct guest_exitlog exitlog;
#endif
};

typedef struct kvm_guest kvm_guest_t;

/**
 * Build an array of existing guest mappings
 *
 * @param vmid, the guest
 * @param gaddr, start address in the guest memory
 * @param pc, number of pages to map
 * @param addr, kernel virtual address to build the bitmask to
 * @param length of the addr in bytes
 * @return zero on success or negative error code on failure
 */
int guest_memmap(uint32_t vmid, void *gaddr, size_t gaddrlen, void *addr,
		 size_t addrlen);

/**
 * Set a guest memory area as shared. If we ever trap on this
 * area while the guest is executing, we will not remove the
 * corresponding host mapping and the host can keep accessing
 * on these pages.
 *
 * @param gpa the guest physical address
 * @param len length of the section in bytes
 * @return zero on success or error code on failure
 */
int set_share(kvm_guest_t *guest, uint64_t gpa, size_t len);

/*
 * Clear a guest share.
 *
 * @param gpa the guest physical address
 * @param len length of the section in bytes
 * @return zero on success or error code on failure.
 */
int clear_share(kvm_guest_t *guest, uint64_t gpa, size_t len);

/*
 * Query if given area is a share.
 *
 * @param gpa the guest physical address
 * @param len length of the section in bytes
 * @return negative error code in failure, 1 if it is, 0 otherwise
 */
int is_share(kvm_guest_t *guest, uint64_t gpa, size_t len);

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
 * @param guest the guest to map to
 * @param vaddr virtual address (ipa) to map
 * @param paddr physical address to map to
 * @param len length of the blob
 * @param prot memory protection bits of the blob
 * @param type type of memory
 * @return zero on success or negative error code on failure
 */
int guest_map_range(kvm_guest_t *guest, uint64_t vaddr, uint64_t paddr,
		    uint64_t len, uint64_t prot);

/**
 * @param guest the guest to unmap from
 * @param addr virtual address (ipa) to unmap
 * @param len length of the blob
 * @param sec 1 in case of page encryption required, 0 otherwise
 * @return number of unmapped pages or negative error code on failure
 */
int guest_unmap_range(kvm_guest_t *guest, uint64_t addr, uint64_t len, uint64_t sec);

/**
 * @param guest
 * @param addr guest physical address to flush
 * @param len length of the flush in bytes
 * @param type 0 for data, 1 for instruction cache flush, 2 for data invalidate
 * @return zero on success or negative error code on failure
 */
int guest_cache_op(kvm_guest_t *guest, uint64_t addr, size_t len, uint32_t type);

/**
 * @param guest
 * @param addr guest physical address to modify
 * @param len length of the section in bytes
 * @param prot protections to drop. bits 0,1,2 are effective: 0 drops read, 1
 *             drops write, 2 drops exec permission on the region
 * @return zero on success or negative error code on failure
 */
int guest_region_protect(kvm_guest_t *guest, uint64_t addr, size_t len, uint64_t prot);

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
 *	   HYP_MKYOUNG zero
 *	   HYP_MKOLD one if the operation was done, zero otherwise
 *	   HYP_ISYOUNG state of the AF flag (1 young, 0 old)
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

/**
 * Get guest context pointer
 *
 * @param vmid the guest virtual machine identifier
 * @param cpuid CPU for which the context is returned
 * @return context address if ok, NULL in case of error
 */
sys_context_t *get_guest_context(uint32_t vmid, uint32_t cpuid);

/**
 * Add a chunk of memory to guest memory pool
 *
 * The arguments are checked for containing information of a valid physically
 * contiguous memory chunk which is currently mapped to host through a 2 stage
 * translation. Chunk will be removed from host mapping and added to guests
 * memory pool. Chunk, once removed from host, is owned by the guest it is
 * assigned to. Chunk is controlled by the hypervisor.
 *
 * @param kvm the kvm instance this chunk is assigned to
 * @param vaddr stage 1 start address of the provided chunk
 * @param paddr physical start address of the provided chunk
 * @param len chunk size
 * @return 0 if valid, negative error code otherwise
 */
int guest_memchunk_add(void *kvm, uint64_t vaddr, uint64_t paddr, uint64_t len);

/**
 * Remove a chunk of memory from guest memory pool
 *
 * Physical address and size must match an entry in the memory pool.
 *
 * @param kvm the kvm instance this chunk is removed from
 * @param paddr physical start address of the chunk to be removed
 * @param len size of the chunk to be removed
 * @return 0 if valid, negative error code otherwise
 */
int guest_memchunk_remove(void *kvm, uint64_t paddr, uint64_t len);

/**
 * Alloc a chunk of memory from guest memory pool
 *
 * @param guest the guest
 * @param minsize minimum size requirement for the chunk
 * @param type the type of allocation this chunk is used for
 * @return index to guest mempool in case of success, negative error code
 *	   otherwise
 */
int guest_memchunk_alloc(kvm_guest_t *guest,
			 size_t minsize,
			 guest_memchunk_user_t type);

/**
 * Add a chunk of memory to guest memory pool
 *
 * Unlike guest_memchunk_add this function is for internal use
 *
 * @param guest the guest
 * @param chunk the chunk to be added to mempool
 * @return index to guest mempool in case of success, negative error code
 *	   otherwise
 */
int __guest_memchunk_add(kvm_guest_t *guest, guest_memchunk_t *chunk);

/*
 * Process host data abort
 *
 * @param vmid, the host vmid
 * @param uint64_t ttbr0_el1
 * @param uint64_t far_el2
 * @param regs array of the given exception registers
 * @return true if the abort was correctly handled
 */
bool host_data_abort(uint64_t vmid, uint64_t ttbr0_el1, uint64_t far_el2,
		     void *regs);

/**
 * Remove a chunk of memory from guest memory pool
 *
 * Unlike guest_memchunk_remove this function is for internal use
 *
 * @param guest the guest
 * @param chunk the chunk to be removed from mempool
 * @return zero in case of success, negative error code otherwise
 */
int __guest_memchunk_remove(kvm_guest_t *guest, guest_memchunk_t *chunk);

/*
 * Crash guest qemu process on access violation
 *
 * @param guest the guest
 * @param regs, array of the userspace exception registers
 * @return true in case of success, false otherwise
 */
bool do_process_core(kvm_guest_t *guest, void *regs);

/*
 * Make the host kernel run its own crash process when illegal access
 * is detected.
 *
 * @param void
 * @return true in case of success, false otherwise
 */
bool do_kernel_crash(void);

#ifdef HOSTBLINDING
static inline void set_blinding_default(kvm_guest_t *guest)
{
	guest->s2_host_access = true;
}
#else
static inline void set_blinding_default(kvm_guest_t *guest)
{
	guest->s2_host_access = false;
}
#endif // HOSTBLINDING

/**
 * Reset guest VCPU registers to initial values, and permit register access
 * from lower ELs.
 *
 * @param kvm    the guest to reset registers
 * @param vcpuid guest VCPU identifier
 * @return zero in case of success, negative error code otherwise
 */
int guest_vcpu_reg_reset(void *kvm, uint64_t vcpuid);

/*
 * Internal use only.
 */
void set_memory_readable(kvm_guest_t *guest);

#endif // __KVM_GUEST_H__
