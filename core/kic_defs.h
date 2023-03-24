// SPDX-License-Identifier: GPL-2.0-only

#ifndef CORE_KIC_DEFS_H_
#define CORE_KIC_DEFS_H_

#define GAD_MAGIC 	0x4e474953
#define GAD_VERSION	0x0300

#define GUEST_ID_MAX_LEN 16
#define SIGNATURE_MAX_LEN 80
#define PUBKEY_MAX_LEN 80
#define KIC_IC_LOADER_MAPPED 1
#define KIC_MAX_IMAGE_SIZE  (64 * SZ_1G)
#define KIC_MAX_DTB_SIZE    (16 * SZ_1K)
#define HASH_LEN 32
#define KIC_IMAGE_COUNT 3

#define KIC_ERROR (-1)
#define KIC_FATAL (-2)

#define KIC_FLAG_LOAD (1 << 3)
#define KIC_FLAG_STORE_ADDR_TO_X0 (1<<4)

typedef enum {
	KIC_NOT_STARTED,
	KIC_LOCKED,
	KIC_RUNNING,
	KIC_VERIFIED_OK,
	KIC_VERIFIED_FAIL,
	KIC_PASSED,
	KIC_FAILED,
} kic_state_t;

typedef struct {
	uint32_t magic;
	uint32_t size;
	uint8_t key[PUBKEY_MAX_LEN];
} public_key_t;


typedef struct {
	uint32_t magic;
	uint32_t version;
	public_key_t sign_key;
	public_key_t enc_key;
	uint8_t signature[SIGNATURE_MAX_LEN];
} guest_cert_t;

typedef struct {
	uint32_t macig;
	uint32_t flags;
	uint32_t size;
	uint32_t offset;
	uint64_t load_address;
	uint8_t hash[HASH_LEN];
} kic_image_t;

/* Guest Authenticated Data */
typedef struct {
	uint32_t macig;
	uint32_t version;
	guest_cert_t cert;
	kic_image_t images[KIC_IMAGE_COUNT];
	uint8_t guest_id[GUEST_ID_MAX_LEN];
	uint8_t signature[SIGNATURE_MAX_LEN];
} gad_t;

#endif /* CORE_KIC_DEFS_H_ */
