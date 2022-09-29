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

/*
 * Should these functions fail, it's not necessarily fatal. We should only
 * be crashing a userspace process.
 */
int host_swap_page(uint64_t addr, uint64_t paddr)
{
	kvm_guest_t *host;
	uint64_t ipa;
	uint64_t *pte;
	int res = 0;

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

	res = encrypt_guest_page(host, addr, paddr, *pte & PROT_MASK_STAGE2);
	if (res) {
		ERROR("0x%lx failed to encrypt, setting to zero. Error %d\n",
		      paddr, res);
		memset((void *)paddr, 0, PAGE_SIZE);
	}
	return res;
}

int host_restore_swap_page(uint64_t addr, uint64_t paddr)
{
	kvm_guest_t *host;
	kvm_page_data *pd;
	uint64_t prot;
	int res = 0;

	if ((addr % PAGE_SIZE) || (paddr % PAGE_SIZE)) {
		ERROR("unaligned swap request\n");
		return -EINVAL;
	}

	host = get_guest(HOST_VMID);
	if (!host)
		panic("no host\n");

	pd = get_range_info(host, addr);
	if (!pd || !pd->nonce) {
		ERROR("page 0x%lx is not encrypted\n", addr);
		goto out_unlock;
	}
	prot = pd->prot;
	spin_unlock(&host->page_data_lock);

	res = decrypt_guest_page(host, addr, paddr, prot);
	if (res) {
		ERROR("0x%lx failed to decrypt, setting to zero. Error %d\n",
		      paddr, res);
		memset((void *)paddr, 0, PAGE_SIZE);
	}
	return res;

out_unlock:
	spin_unlock(&host->page_data_lock);
	return res;
}
