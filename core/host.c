// SPDX-License-Identifier: GPL-2.0-only

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>

#include "host.h"
#include "hvccall.h"
#include "armtrans.h"
#include "hyplogs.h"
#include "helpers.h"
#include "guest.h"
#include "mm.h"

int host_swap_page(uint64_t addr, uint64_t paddr)
{
	kvm_guest_t *host;
	uint64_t ipa;
	uint64_t *pte;

	if ((addr % PAGE_SIZE) || (paddr % PAGE_SIZE)) {
		ERROR("unaligned swap request\n");
		return -EINVAL;
	}

	host = get_guest(HOST_VMID);
	if (!host)
		panic("no host\n");

	/* Host, so yes it's IPA */
	ipa = pt_walk(host, STAGE2, paddr, &pte);
	if (ipa == ~0UL) {
		ERROR("address 0x%lx not translatable?\n", addr);
		return -EINVAL;
	}
	if (ipa != paddr)
		panic("host address mismatch?\n");

	return encrypt_guest_page(host, addr, paddr, *pte & PROT_MASK_STAGE2);
}

int host_restore_swap_page(uint64_t addr, uint64_t paddr)
{
	kvm_guest_t *host;
	kvm_page_data *pd;
	int res;

	if ((addr % PAGE_SIZE) || (paddr % PAGE_SIZE)) {
		ERROR("unaligned swap request\n");
		return -EINVAL;
	}

	host = get_guest(HOST_VMID);
	if (!host)
		panic("no host\n");

	pd = get_range_info(host, addr);
	if (!pd)
		return 0;

	res = decrypt_guest_page(host, addr, paddr, pd->prot);
	if (res)
		panic("failed to decrypt host page, error %d\n", res);

	return 0;
}
