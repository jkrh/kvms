// SPDX-License-Identifier: GPL-2.0-only

#ifndef CORE_KIC_DEFS_H_
#define CORE_KIC_DEFS_H_

#define GAD_MAGIC 	0x4e474953
#define GAD_VERSION	0x0201

#define GUEST_ID_MAX_LEN 16
#define SIGNATURE_MAX_LEN 80
#define PUBKEY_MAX_LEN 80
#define KIC_IC_LOADER_MAPPED 1
#define KIC_MAX_IMAGE_SIZE  (64 * SZ_1G)
#define KIC_MAX_DTB_SIZE    (16 * SZ_1K)

#define KIC_ERROR (-1)
#define KIC_FATAL (-2)

typedef enum {
	KIC_NOT_STARTED,
	KIC_LOCKED,
	KIC_RUNNING,
	KIC_VERIFIED_OK,
	KIC_VERIFIED_FAIL,
	KIC_PASSED,
	KIC_FAILED,
} kic_state_t;

/* Guest Authenticated Data */
typedef struct {
	uint32_t macig;
	uint32_t version;
	uint64_t image_size;
	uint64_t dtb;
	uint64_t dtb_size;
	uint8_t guest_id[GUEST_ID_MAX_LEN];
	uint32_t pubkey_size;
	uint8_t guest_pubkey[PUBKEY_MAX_LEN];
	uint8_t signature[SIGNATURE_MAX_LEN];
} gad_t;

#endif /* CORE_KIC_DEFS_H_ */
