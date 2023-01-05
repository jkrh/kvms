#!/bin/bash -e

[ -z "$SYMHDR" ] && SYMHDR="$BASE_DIR/core/kvmsyms.h"
[ -z "$VMLINUX" ] && VMLINUX="$KERNEL_DIR/vmlinux"
[ -z "$SYMPFX" ] && SYMPFX="__kvms_"

HYP_TEXT_START=$(printf "%u" `aarch64-linux-gnu-readelf -Ws $VMLINUX |grep __hyp_text_start|awk '{print "0x"$2 }' | head -n 1`)
HYP_TEXT_END=$(printf "%u" `aarch64-linux-gnu-readelf -Ws $VMLINUX |grep __hyp_text_end|awk '{print "0x"$2 }' | head -n 1`)

cat << EOF > $SYMHDR
/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __KVMCALLS__
#define __KVMCALLS__

#include <stdint.h>

/* This is a generated header. Don't modify. */

static uint64_t kvm_jump_vector[] = {
EOF

ALLSYMS=`${CROSS_COMPILE}readelf -Ws $VMLINUX |grep $SYMPFX |grep FUNC || true`
if [ -n "${ALLSYMS}" ]; then
while IFS= read -r LINE ; do
	SYMVALS=`echo $LINE | awk '{ print "0x"$2 }'`
	SYMNAME=`echo $LINE | awk '{ print $8 }'`
	SYMVAL=$(printf "%u" "$SYMVALS")

	if [[ $SYMVAL -gt $HYP_TEXT_START && $SYMVAL -lt $HYP_TEXT_END ]]; then
		echo "	$SYMVALS, // $SYMNAME" >> $SYMHDR
	fi
done <<< "$ALLSYMS"
fi

cat << EOF >> $SYMHDR
};

#define jump_count (sizeof(kvm_jump_vector)/sizeof(kvm_jump_vector[0]))
#endif // __KVMCALLS__
EOF
