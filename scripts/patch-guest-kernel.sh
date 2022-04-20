
#!/bin/bash
set -e

# Script to build patched kernel image

# This script expects that modprobe nbd max_part=8 has been executed before

# if unmount is not done or it failed, next iteration wont work until unmount and disconnect is done
# umount /mnt
# kpartx -vd /dev/nbd0
# qemu-nbd --disconnect /dev/nbd0


KERNEL_VERSION=5.10.108
UBUNTU_BASE=ubuntu-base-20.04.2-base-arm64.tar.gz
PATCH_FILE=../patches/guest/0001-kvm-encrypted-memory-draft-for-arm64-development.patch

usage() {
	echo "$0 -k <kernel version>|-p <patch file>"
	echo ""
	echo "Example:"
	echo "	$0 -k 5.10.108 -p ../patches/guest/0001-kvm-encrypted-memory-draft-for-arm64-development.patch"
	echo ""
	echo "	Builds patched kernel and copies the resulting Image to current dir"
	exit 1
}

while getopts "h?k:p:" opt; do
  case "$opt" in
    h|\?)
      usage
      exit 0
      ;;
    k)  KERNEL_VERSION=$OPTARG
      ;;
    p)  PATCH_FILE=$OPTARG
      ;;
  esac
done

echo "Using:"
echo "KERNEL_VERSION=$KERNEL_VERSION"
echo "PATCH_FILE=$PATCH_FILE"
echo "UBUNTU_BASE=$UBUNTU_BASE"

# setup ubuntu image
qemu-img create -f qcow2 /tmp/ubuntu.img 10G 
qemu-nbd --connect=/dev/nbd0 /tmp/ubuntu.img
echo 'type=83' | sfdisk /dev/nbd0 
kpartx -a /dev/nbd0
mkfs.ext4 /dev/mapper/nbd0p1
mount /dev/mapper/nbd0p1 /mnt

wget -N http://cdimage.ubuntu.com/ubuntu-base/releases/20.04.4/release/${UBUNTU_BASE} -P /tmp
tar xf /tmp/${UBUNTU_BASE} -C /mnt
wget -N https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${KERNEL_VERSION}.tar.xz -P /tmp
tar xf /tmp/linux-${KERNEL_VERSION}.tar.xz
cd linux-${KERNEL_VERSION}
patch -p1 < ${PATCH_FILE}
make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64 INSTALL_MOD_STRIP=1 INSTALL_MOD_PATH=/mnt/usr -j8  defconfig Image modules modules_install
cd ..
cp linux-${KERNEL_VERSION}/arch/arm64/boot/Image .

# cleanup nbd mount
umount /mnt
kpartx -vd /dev/nbd0 # https://www.enricozini.org/blog/2017/debian/egg-walking-with-qemu-nbd-and-kpartx/
qemu-nbd --disconnect /dev/nbd0
