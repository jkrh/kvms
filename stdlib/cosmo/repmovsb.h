#ifndef COSMOPOLITAN_LIBC_INTRIN_REPMOVSB_H_
#define COSMOPOLITAN_LIBC_INTRIN_REPMOVSB_H_

void repmovsb(void **dest, void **src, size_t cx) {
  char *di = (char *)*dest;
  char *si = (char *)*src;
  while (cx) *di++ = *si++, cx--;
  *dest = di, *src = si;
}

#endif /* COSMOPOLITAN_LIBC_INTRIN_REPMOVSB_H_ */
