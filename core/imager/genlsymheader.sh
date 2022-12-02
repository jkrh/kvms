#!/bin/bash -e

LSYMBOLSFILE=$OUTDIR/hyp-binary.o
LSYMBOLSHEADER=$OUTDIR/lsymbols.h

echo "Create $LSYMBOLSHEADER"

LSTARTNAME="HYP_BIN_START"
LSTARTSYM=$(${CROSS_COMPILE}objdump -t $LSYMBOLSFILE |grep _o_lz4_start |awk '{print $5}')
LSIZENAME="HYP_BIN_SIZE"
LSIZE=$(${CROSS_COMPILE}objdump -t $LSYMBOLSFILE |grep _o_lz4_size |awk '{print $1}')

echo "#ifndef _LSYMBOLS_H_" > $LSYMBOLSHEADER
echo "#define _LSYMBOLS_H_" >> $LSYMBOLSHEADER
echo "#define $LSTARTNAME ${LSTARTSYM}" >> $LSYMBOLSHEADER
echo "#define $LSIZENAME 0x${LSIZE}UL" >> $LSYMBOLSHEADER
echo "#endif /*_LSYMBOLS_H_*/" >> $LSYMBOLSHEADER
