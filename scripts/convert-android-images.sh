#!/bin/bash

usage() {
	echo "$0 <android build dir> <output dir>"
}

[ -z "$1" ] && usage && exit 1
[ -z "$2" ] && usage && exit 1

ANDROID_DIR=$1
OUTPUT_DIR=$2

set -e
mkdir -p $OUTPUT_DIR
IMAGES=`find $ANDROID_DIR/out/target/product -name \*.img | grep -v obj`

for IMAGE in $IMAGES; do
	echo $IMAGE

	IMAGE_BASENAME=`basename $IMAGE`
	IMAGE_BASENAME="${IMAGE_BASENAME/img/'qcow2'}"
	qemu-img convert -p -f raw -O qcow2 $IMAGE $OUTPUT_DIR/$IMAGE_BASENAME
done
cp out/target/product/generic_arm64/kernel-ranchu $OUTPUT_DIR
