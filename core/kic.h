// SPDX-License-Identifier: GPL-2.0-only

#ifndef CORE_KIC_H_
#define CORE_KIC_H_

#define KIC_VERSION 0x0100

#define GUEST_ID_MAX_LEN 16
#define SIGNATURE_MAX_LEN 72
typedef struct {
	uint32_t version;
	uint32_t orig_instr; /* Copy of first bytes of original image */
	uint8_t guest_id[GUEST_ID_MAX_LEN];
	uint8_t signature[SIGNATURE_MAX_LEN];
} sign_params_t;

#endif /* CORE_KIC_H_ */
