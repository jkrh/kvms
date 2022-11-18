#ifndef COSMOPOLITAN_LIBC_KOMPRESSOR_KOMPRESSOR_H_
#define COSMOPOLITAN_LIBC_KOMPRESSOR_KOMPRESSOR_H_

#include <stdint.h>
#include <string.h>

#define _Hide

#if 0
/*───────────────────────────────────────────────────────────────────────────│─╗
│ cosmopolitan § standard library » compression                            ─╬─│┼
╚────────────────────────────────────────────────────────────────────────────│*/
#endif

struct RlDecode {
  uint8_t repititions;
  uint8_t byte;
};

void rldecode(void *dest, const struct RlDecode *) _Hide;
void rldecode2(void *dest, const struct RlDecode *) _Hide;
uint8_t *lz4check(void *data) _Hide;
void *lz4cpy(void *dest, void *blockdata, size_t blocksize) _Hide;
void *lz4decode(void *dest, const void *src) _Hide;

#endif /* COSMOPOLITAN_LIBC_KOMPRESSOR_KOMPRESSOR_H_ */
