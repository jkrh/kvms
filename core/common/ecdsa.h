// SPDX-License-Identifier: GPL-2.0-only

#ifndef __CORE_COMMON_ECDSA_H__
#define __CORE_COMMON_ECDSA_H__

int do_ecdsa(uint8_t *sign, uint8_t *hash, uint8_t *pub, size_t pub_size);

#endif /* __CORE_COMMON_ECDSA_H__ */
