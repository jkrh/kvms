/*
 * product_api.h function prototypes that
 * the product implementation is expected to implement.
 */

#ifndef __PRODUCT_API_H__
#define __PRODUCT_API_H__

#include <stdbool.h>

/**
 * is_secboot - Query if secure boot is enabled.
 *
 * @return true if secure boot is enabled,
 * 	   false otherwise.
 */
bool is_secboot(void);


#endif /* __PRODUCT_API_H__ */
