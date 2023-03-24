// SPDX-License-Identifier: GPL-2.0-only

#ifndef CORE_KIC_H_
#define CORE_KIC_H_
#include "kic_defs.h"

#ifndef KIC_DISABLE
extern spinlock_t kic_lock;
#endif

/***
 * Handle modifications to S2-mapping when kernel integrity check is running
 * @param guest the guest
 * @param vaddr IPA address to map
 * @param vaddr paddr physical address to map.
 */
static inline int handle_kic_mapping(kvm_guest_t *guest,
				     uint64_t vaddr, uint64_t *paddr)
{
#ifndef KIC_DISABLE
	if (unlikely(guest->kic_status < KIC_PASSED))
		return handle_icldr_mapping(guest, vaddr, paddr);
#endif
	return 0;
}

/***
 * Initiate guest kernel integrity check when guest is started first time
 * @param gst the guest
 * @param ctx vcpu register context
 */
static inline void handle_kic_start(kvm_guest_t *gst, struct vcpu_context *ctx)
{
#ifndef KIC_DISABLE
	if (unlikely(gst->kic_status == KIC_NOT_STARTED)) {
		spin_lock(&kic_lock);
		if (gst->kic_status == KIC_NOT_STARTED) {
			gst->kic_status = KIC_LOCKED;
			/* store the original start address */
			ctx->regs.regs[1] = ctx->regs.pc;
		} else {
			/* Only one core can do KIC on the guest */
			ERROR("More than one core is running on KIC\n");
		}
	}
#endif
}

/***
 * Remap the integrity loader to hypervisor internal address
 * @param guest the guest
 * @param icloader address of icloader (ipa)
 * @return zero in case of success
 *
 */
int remap_icloader(void *g, uint64_t image);

/***
 * Initiate guest kernel & device tree check
 * @param guest the guest
 * @param start_page integrity check start page (ipa)
 * @return zero in case of success
 */
int image_check_init(void *guest, uint64_t start_page);

/***
 * Do image integrity check. The check is done over signature parameters
 * , device tree (if defined) and the kernel image
 *
 * @param guest the guest
 * @param kernel image start address (ipa)
 * @param laddr address of load address table
 * @return zero in case of success
 */
int check_guest_image(void *guest, uint64_t laddr);
/*
 * Internal use only.
 */
#endif /* CORE_KIC_H_ */
