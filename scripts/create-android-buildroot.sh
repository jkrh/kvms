#!/bin/bash

set -e

USER=$(whoami)
UBUNTU_BASE=https://cdimage.ubuntu.com/ubuntu-base/releases/focal/release/ubuntu-base-20.04.5-base-amd64.tar.gz
ANDROID_PKGS="git-core gnupg flex bison build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 libncurses5 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig libxml-simple-perl rsync libssl-dev python3 python bc vim ccache cpio"
INSTALL="n"
DROID=""

usage()
{
	echo "$0 -c <chroot dir> -a <android dir> -i <reinstall chroot, y|n>"
}

while getopts "h?a:c:i" opt; do
	case "$opt" in
		h|\?)
			usage
			exit 0
		;;
		a) DROID=$OPTARG
		;;
		c) CHROOTDIR=$OPTARG
		;;
		i) INSTALL=y
		;;
	esac
done

if [ "x$CHROOTDIR" = "x" ]; then
	usage
	exit 1
fi

do_unmount()
{
	if [[ $(findmnt -M "$1") ]]; then
		sudo umount $1 || true
	fi
}

do_unmount_all()
{
	for MNT in proc sys mnt dev/shm dev/pts dev; do
		do_unmount $CHROOTDIR/$MNT
	done
	do_unmount $CHROOTDIR/home/$USER/$DROIDBASE
}

cleanup()
{
	kill $(jobs -p) > /dev/null 2>&1
	do_unmount_all
}

do_mounts()
{
	for MNT in proc sys mnt dev dev/shm dev/pts; do
		[[ $(findmnt -M $CHROOTDIR/$MNT ) ]] || sudo mount --bind /$MNT $CHROOTDIR/$MNT
	done
}

install_buildroot()
{
	do_unmount_all
	sudo rm -rf $CHROOTDIR; mkdir -p $CHROOTDIR
	wget -c $UBUNTU_BASE
	tar xf `basename $UBUNTU_BASE` -C $CHROOTDIR
	sudo chmod 1777 $CHROOTDIR/tmp
	sudo chmod 1777 $CHROOTDIR/var/tmp

	echo "nameserver 8.8.8.8" > $CHROOTDIR/etc/resolv.conf
	do_mounts
	sudo chroot $CHROOTDIR ln -sf /proc/self/mounts /etc/mtab

	DEBIAN_FRONTEND=noninteractive sudo -E chroot $CHROOTDIR apt-get update
	DEBIAN_FRONTEND=noninteractive sudo -E chroot $CHROOTDIR apt-get install -y $ANDROID_PKGS
	DEBIAN_FRONTEND=noninteractive sudo -E chroot $CHROOTDIR useradd -m -k /etc/skel -s /bin/bash $USER
}

trap cleanup SIGHUP SIGINT SIGTERM

if [ $INSTALL = "y" ]; then
	install_buildroot
fi
do_mounts

if [ "x$DROID" != "x" ]; then
	DROIDBASE=$(basename $DROID)
	mkdir -p $CHROOTDIR/home/$USER/$DROIDBASE
	[[ $(findmnt -M $CHROOTDIR/home/$USER/$DROIDBASE) ]] || sudo mount --bind $DROID $CHROOTDIR/home/$USER/$DROIDBASE
fi

sudo chroot $CHROOTDIR /bin/bash
do_unmount_all
