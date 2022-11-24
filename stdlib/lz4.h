#include <stdint.h>

#ifndef UNSAFE_LZ4
uint64_t lz4dec(const void *src, void *dst, uint64_t srcsz);
#else
uint64_t lz4dec(const void *src, void *dst, uint64_t srcsz, uint64_t dstsz);
#endif
