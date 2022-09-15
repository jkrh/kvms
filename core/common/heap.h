/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __HEAP_H__
#define __HEAP_H__

#include <stdint.h>
#include <stddef.h>

#include "commondefines.h"

#ifndef MALLOC_POOL_SIZE
#define MALLOC_POOL_SIZE \
        ROUND_UP((MAX_PAGING_BLOCKS * MAX_GUESTS * sizeof(kvm_page_data)), \
        PAGE_SIZE)
#endif

int set_heap(void *h, size_t sz);
uint8_t *get_static_buffer(size_t size);

#endif
