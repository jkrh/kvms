/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include "helpers.h"
#include "platform_crypto.h"
#ifdef USE_HW_CRYPTO

/* TODO:
 * Study if it is better to save simd registers in fpsimd trap.
 * It is a little bit faster because register save/restore is done only
 * when it is needed.
 * Problems: fpsimd trap is an exception from EL2 to EL2 so it overwrites
 * elr_el2 and spsr_el2 registers, Registers have to be stored/restored on
 * HVC entry/exit. Also their values are used in HVC, so there have to be a
 * way to read their entry value in HVC.
 */
void get_platform_crypto_ctx(platform_crypto_ctx_t *p)
{
	uint64_t tmp = 0;

	tmp = read_reg(CPTR_EL2);
	p->cptr_el2_tfp = !!(tmp & CPTR_EL2_TFP);
	if (p->cptr_el2_tfp)
		write_reg(CPTR_EL2, (tmp & ~CPTR_EL2_TFP));
	__store_simd(&p->fpsimd);
}

void give_platform_crypto_ctx(platform_crypto_ctx_t *p)
{
	__restore_simd(&p->fpsimd);
	if (p->cptr_el2_tfp)
		write_reg(CPTR_EL2, read_reg(CPTR_EL2) | CPTR_EL2_TFP);
}
#endif
