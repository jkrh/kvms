#!/bin/bash -e

SYSTEM_MAP=$1/System.map

#
# Is this a awk bug or what is it?
#
# awk '{ printf "#ifndef %s\n#define %s 0x%s\n#endif\n", $3, $3, $1 } ' $SYSTEM_MAP > tmp.h
#
# awk5 looks broken, awk4 is ok..
#

#
# Strip the system.map first.
#

grep -Ew '_text|_etext|_data|__bss_stop|vdso_start|vdso_end|__start_rodata|__end_rodata' \
     $SYSTEM_MAP | grep -v '\.' > tmp.out
#grep "__" tmp.out > tmp2.out
grep -v @ tmp.out > tmp2.out
grep -v "__UNIQUE_ID" tmp2.out > tmp.out
SMAP=tmp.out

echo "#ifndef _KERNEL_SYMS_
#define _KERNEL_SYMS_
" > kaddr.h

while read line; do
  ADDR=${line:1:17}
  SYM=${line:19:100}__addr
  ADDR=${ADDR:0:-2}
  echo "#ifndef $SYM
#define $SYM 0x$ADDR
#endif" >> kaddr.h
done < $SMAP

echo "#endif // _KERNEL_SYMS_" >> kaddr.h
rm -f *.out
