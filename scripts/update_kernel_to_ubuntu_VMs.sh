
#!/bin/bash
set -e

# Run this script with sudo

# Script to build patched kernel image and install modules to ubuntu20 image
# Script mounts given image to /tmp/host and then mounts the guest image from inside host image.
# Build given kernel version and install modules to both guest and host images and then unmount them.

# This script expects that modprobe nbd max_part=8 has been executed before
# if unmount is not done or it failed, next iteration wont work until unmount and disconnect is done

umount /tmp/guest || true
qemu-nbd --disconnect /dev/nbd1 || true
umount /tmp/host || true
qemu-nbd --disconnect /dev/nbd0 || true

KERNEL_VERSION=5.10.108
PATCH_FILE=../patches/guest/0001-kvm-encrypted-memory-draft-for-arm64-development.patch

usage() {
	echo "$0 -i <VM image> -k <kernel version>|-p <patch file>"
	echo ""
	echo "Example:"
	echo "	$0 -k ubuntu20.qcow2 -k 5.10.108 -p ../patches/guest/0001-kvm-encrypted-memory-draft-for-arm64-development.patch"
	echo ""
	echo "	Builds patched kernel, installs modules to VMs and copies the resulting Image to current dir"
  echo "  Run this script with sudo"
  echo "  modprobe nbd max_part=8 needs to be executed before running this."
	exit 1
}

while getopts "h?k:p:i:" opt; do
  case "$opt" in
    h|\?)
      usage
      exit 0
      ;;
    k)  KERNEL_VERSION=$OPTARG
      ;;
    p)  PATCH_FILE=$OPTARG
      ;;
    i)  IMAGE_FILE=$OPTARG
      ;;
  esac
done

echo "Using:"
echo "KERNEL_VERSION=$KERNEL_VERSION"
echo "PATCH_FILE=$PATCH_FILE"
echo "IMAGE_FILE=$IMAGE_FILE"

mkdir -p /tmp/host
mkdir -p /tmp/guest

# mount IMAGE_FILE
echo "qemu-nbd --connect=/dev/nbd0 $IMAGE_FILE"
qemu-nbd --connect=/dev/nbd0 $IMAGE_FILE
mount /dev/nbd0p1 /tmp/host

# mount guest VM stored inside host
qemu-nbd --connect=/dev/nbd1 /tmp/host/home/ubuntu/vm/ubuntu20/ubuntu20.qcow2
mount /dev/nbd1p1 /tmp/guest

wget -N https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${KERNEL_VERSION}.tar.xz -P /tmp
tar xf /tmp/linux-${KERNEL_VERSION}.tar.xz
cd linux-${KERNEL_VERSION}
# if patch is already applied, return 0
# if patching fails still returns 0 :(
patch -p1 --forward < ${PATCH_FILE} || true
make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64 INSTALL_MOD_STRIP=1 INSTALL_MOD_PATH=/tmp/host -j8  defconfig Image modules modules_install
make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64 INSTALL_MOD_STRIP=1 INSTALL_MOD_PATH=/tmp/guest -j8  modules_install
cd ..
cp linux-${KERNEL_VERSION}/arch/arm64/boot/Image .

# unmount VMs and cleanup nbd mounts
umount /tmp/guest
qemu-nbd --disconnect /dev/nbd1
umount /tmp/host 
qemu-nbd --disconnect /dev/nbd0
