#!/bin/bash

CURDIR=$PWD
MNTDIR=$CURDIR/tmp
PARTITION=p2

wget -c  https://cdimage.ubuntu.com/releases/20.10/release/ubuntu-20.10-preinstalled-desktop-arm64+raspi.img.xz
xz -d ubuntu-20.10-preinstalled-desktop-arm64+raspi.img.xz

LOOPDEVICE=`losetup -f`
losetup -P $LOOPDEVICE ubuntu-20.10-preinstalled-desktop-arm64+raspi.img
mkdir -p $MNTDIR
mount $LOOPDEVICE$PARTITION $MNTDIR

cd ../oss/linux
make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64 INSTALL_MOD_STRIP=1 INSTALL_MOD_PATH=$MNTDIR/usr modules_install
cd $CURDIR

umount $MNTDIR
losetup -d $LOOPDEVICE
rm -rf $MNTDIR

chmod 777 ubuntu-20.10-preinstalled-desktop-arm64+raspi.img
