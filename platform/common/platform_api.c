/* SPDX-License-Identifier: GPL-2.0-only */

/**
 * Default platform implementation. Override in platform specific code if there
 * is a need.
 */
#include "commondefines.h"
#include "bits.h"
#include "helpers.h"
#include "hyplogs.h"
#include "platform_api.h"
#include "product_mmap.h"
#include "mbedtls/md.h"

#define NUM_DENYRANGE	16
#define PLATFORM_SALT "example salt"
#define PLATFORM_SALT_SIZE (sizeof(PLATFORM_SALT))
#define PLATFORM_SECRET_KEY "This must be a secret value!"

static struct memrange denyrange[NUM_DENYRANGE];

WEAK_SYM
int platform_init_guest(uint32_t vmid)
{
	LOG("vmid %ld\n", vmid);

	return 0;
}

WEAK_SYM
int platform_allow_guest_smc(register_t cn, register_t a1, register_t a2,
			     register_t a3, register_t a4, register_t a5,
			     register_t a6, register_t a7)
{
	return 0;
}

WEAK_SYM
void platform_early_setup(void)
{
	uint64_t hcr_el2, cnthctl_el2;

	/* 64 bit only, Trap SMCs */
	hcr_el2 = 0;
	bit_set(hcr_el2, HCR_RW_BIT);
	bit_set(hcr_el2, HCR_VM_BIT);
	bit_set(hcr_el2, HCR_NV2_BIT);
	bit_set(hcr_el2, HCR_TVM_BIT);
	write_reg(HCR_EL2, hcr_el2);

	/* EL1 timer access */
	cnthctl_el2 = 0;
	bit_set(cnthctl_el2, CNTHCTL_EL1PCTEN_BIT);
	bit_set(cnthctl_el2, CNTHCTL_EL1PCEN_BIT);
	bit_set(cnthctl_el2, CNTHCTL_ENVTEN_BIT);
	write_reg(CNTHCTL_EL2, cnthctl_el2);
	write_reg(CNTVOFF_EL2, 0);

	/* Processor id */
	write_reg(VPIDR_EL2, read_reg(MIDR_EL1));

	/* Use linux mair */
	write_reg(MAIR_EL2, PLATFORM_MAIR_EL2);

	isb();
}

WEAK_SYM
void platform_mmu_prepare(void)
{
	kvm_guest_t *host;

	if (PLATFORM_VTCR_EL2 != 0)
		write_reg(VTCR_EL2, PLATFORM_VTCR_EL2);

	if (PLATFORM_TCR_EL2 != 0)
		write_reg(TCR_EL2, PLATFORM_TCR_EL2);

	host = get_guest(HOST_VMID);
	if (!host)
		panic("");

	write_reg(TTBR0_EL2, (uint64_t)host->EL2S1_pgd);
	write_reg(VTTBR_EL2, (uint64_t)host->EL1S2_pgd);
	set_current_vmid(HOST_VMID);

	dsb();
	isb();
}

static inline uint8_t reverse(uint8_t b)
{
	return (uint8_t)((b * 0x0202020202UL & 0x010884422010UL) % 1023UL);
}

/* platform_get_static_key() is example code only. It must be replaced with
 * secret one on real platforms.
 */
WEAK_SYM
int platform_get_static_key(uint8_t *key, size_t key_size,
			      void *salt, size_t salt_size)
{
	mbedtls_md_handle_t md;

	md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (md == NULL)
		return -1;

	return mbedtls_hkdf(md, PLATFORM_SALT, PLATFORM_SALT_SIZE,
			   PLATFORM_SECRET_KEY, sizeof(PLATFORM_SECRET_KEY),
			   salt, salt_size,
			   key, key_size);
}

WEAK_SYM
int platform_entropy(uint8_t *entropy, size_t len)
{
	uint64_t v1, v2;
	uint8_t b1, b2;

	/*
	 * Our 'very secure' development entropy.
	 */
	while (len-- > 0) {
		wfe();
		v1 = read_reg(CNTPCT_EL0);
		b1 = v1 & 0xFF;

		wfe();
		v2 = read_reg(CNTPCT_EL0);
		b2 = v2 & 0xFF;

		b2 = reverse(b2);
		b1 ^= b2;
		entropy[len] = b1;
	}
	return 0;
}

WEAK_SYM
void platform_init_denyrange(void)
{
	int i;

	if (sizeof(noaccess) > sizeof(denyrange))
		panic("No space to initialize denied ranges!\n");

	for (i = 0; i < sizeof(noaccess) / sizeof(struct memrange); i++) {
		denyrange[i].start = noaccess[i].start;
		denyrange[i].end = noaccess[i].end;
	}
}

WEAK_SYM
int platform_range_permitted(uint64_t pstart, size_t len)
{
	int entry = 0, res = 0;
	uint64_t pend = (pstart + len) - 1;

	if (pend <= pstart)
		return res;

	while (denyrange[entry].end) {
		if ((denyrange[entry].start <= pstart) &&
		    (pstart <= denyrange[entry].end))
			break;
		if ((denyrange[entry].start <= pend) &&
		    (pend <= denyrange[entry].end))
			break;
		if ((pstart < denyrange[entry].start) &&
		    (denyrange[entry].end < pend))
			break;
		entry++;
	}

	if (!denyrange[entry].end)
		res = 1;

	return res;
}

WEAK_SYM
void platform_add_denyrange(uint64_t pstart, size_t len)
{
	uint64_t pend = (pstart + len) - 1;
	int i;

	if (pend <= pstart) {
		ERROR("Invalid range\n");
		return;
	}

	if (denyrange[NUM_DENYRANGE-1].end) {
		ERROR("No space to add denied ranges!\n");
		return;
	}

	for (i = 0; i < NUM_DENYRANGE; i++) {
		if (denyrange[i].end)
			continue;

		denyrange[i].start = pstart;
		denyrange[i].end = pend;
		break;
	}
}
