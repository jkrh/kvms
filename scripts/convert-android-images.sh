#!/bin/bash

usage() {
	echo "$0 <android build dir> <output dir> <kernel dir>"
}

[ -z "$1" ] && usage && exit 1
[ -z "$2" ] && usage && exit 1
[ -z "$3" ] && usage && exit 1

ANDROID_DIR=$1
OUTPUT_DIR=$2
KERNEL_DIR=$3

set -e
mkdir -p $OUTPUT_DIR/.tmp/root $OUTPUT_DIR/.tmp/sys $OUTPUT_DIR/.tmp/vendor

qemu-img create $OUTPUT_DIR/rootfs.img 5G
mkfs.ext4 $OUTPUT_DIR/rootfs.img

sudo mount -o loop $OUTPUT_DIR/rootfs.img $OUTPUT_DIR/.tmp/root
sudo mount -r -o loop $ANDROID_DIR/out/target/product/generic_arm64/system.img $OUTPUT_DIR/.tmp/sys
sudo mount -r -o loop $ANDROID_DIR/out/target/product/generic_arm64/vendor.img $OUTPUT_DIR/.tmp/vendor
sudo cp -a $OUTPUT_DIR/.tmp/sys/* $OUTPUT_DIR/.tmp/root/
sudo cp -a $OUTPUT_DIR/.tmp/vendor/* $OUTPUT_DIR/.tmp/root/vendor/

sudo cat << EOF > $OUTPUT_DIR/.tmp/root/vendor/etc/fstab.ranchu
/dev/block/sdb          /data           ext4    noatime,nosuid,nodev,nomblk_io_submit,errors=panic   wait,check,quota,reservedsize=128M,first_stage_mount
/dev/block/sdc          /cache          ext4    noatime,nosuid,nodev,nomblk_io_submit,errors=panic   wait,check,quota,reservedsize=12
EOF

cd $KERNEL_DIR
sudo make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- INSTALL_MOD_STRIP=1 INSTALL_MOD_PATH=$OUTPUT_DIR/.tmp/vendor modules_install
cd -
sudo umount $OUTPUT_DIR/.tmp/root
sudo umount $OUTPUT_DIR/.tmp/sys
sudo umount $OUTPUT_DIR/.tmp/vendor
rm -rf $OUTPUT_DIR/.tmp
