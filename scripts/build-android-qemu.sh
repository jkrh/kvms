#!/bin/bash

#
# Tested on ubuntu 20.n. You need to have qemu-user-static and binfmt-support
# installed.
#

TOOLDIR=$BASE_DIR/buildtools
QEMU_USER=`which qemu-aarch64-static`
QEMU_PATCHFILE="$BASE_DIR/patches/0001-target-ranchu-add-support-for-android-ranchu-board.patch"

if [ "x$STATIC" = "x1" ]; then
echo "Static build"
SSTATIC="--enable-static"
QSTATIC="--static"
else
echo "Full sysroot build"
SSTATIC=""
QSTATIC=""
fi

if [ "x$OPENGL" = "x1" ]; then
echo "OpenGL enabled"
OPENGL="--enable-opengl"
else
echo "OpenGL disabled"
OPENGL="--disable-opengl"
fi

set -e

#
# Note: cross-compilation is also possible, these can be passed through.
#

unset CC
unset LD
unset CXX
unset AR
unset CPP
unset CROSS_COMPILE
unset CFLAGS
unset LDFLAGS
unset ASFLAGS
unset INCLUDES
unset WARNINGS
unset DEFINES

export PATH=$TOOLDIR/bin:$TOOLDIR/usr/bin:/bin:/usr/bin

NJOBS=`nproc`
PKGLIST=`cat $BASE_DIR/scripts/package.list`

cleanup()
{
	sudo umount $BASE_DIR/oss/ubuntu/qemu
}
trap cleanup SIGHUP SIGINT SIGTERM EXIT

do_clean()
{
	sudo rm -rf $BASE_DIR/oss/ubuntu
	cd $BASE_DIR/oss/qemu; sudo git clean -xfd || true
}

do_patch()
{
	cd $BASE_DIR/oss/qemu
	OUT=$(git apply --check $QEMU_PATCHFILE 2>&1 | wc -l)
	if [ $OUT != "0" ]; then
		echo "Skipping qemu patch, already applied?"
	else
		echo "Patching qemu to support ranchu"
		git am $QEMU_PATCHFILE
	fi
}

do_sysroot()
{
	mkdir -p $BASE_DIR/oss/ubuntu
	cd $BASE_DIR/oss/ubuntu
	wget -c http://cdimage.debian.org/mirror/cdimage.ubuntu.com/ubuntu-base/releases/20.04/release/ubuntu-base-20.04.1-base-arm64.tar.gz
	tar xf ubuntu-base-20.04.1-base-arm64.tar.gz
	echo "nameserver 8.8.8.8" > etc/resolv.conf
	cp $QEMU_USER usr/bin
	sudo chmod a+rwx tmp
	DEBIAN_FRONTEND=noninteractive sudo -E chroot . apt-get update
	DEBIAN_FRONTEND=noninteractive sudo -E chroot . apt-get -y install $PKGLIST
}

do_spice()
{
	cd $BASE_DIR/oss/ubuntu
	sudo rm -rf spice-0.14.3
	wget https://www.spice-space.org/download/releases/spice-server/spice-0.14.3.tar.bz2
	tar xf spice-0.14.3.tar.bz2
	sudo -E chroot . sh -c "cd spice-0.14.3; ./configure --prefix=/usr $SSTATIC --disable-celt051 ; make -j$NJOBS ; make install"
}

do_qemu()
{
	mkdir -p $BASE_DIR/oss/ubuntu/qemu
	sudo mount --bind $BASE_DIR/oss/qemu $BASE_DIR/oss/ubuntu/qemu
	mkdir -p $BASE_DIR/oss/ubuntu/qemu/build
	cd $BASE_DIR/oss/ubuntu
	sed -i '4159i spice_libs="  $spice_libs -L/usr/lib/aarch64-linux-gnu -lopus -ljpeg -lm"' qemu/configure
	sudo -E chroot . sh -c "cd qemu/build; ../configure --prefix=/usr --target-list=aarch64-softmmu --with-git-submodules=ignore --enable-kvm --enable-spice $OPENGL $QSTATIC"
	sudo -E chroot . sh -c "cd qemu/build; make -j$NJOBS; make install"
}
do_clean
do_sysroot
do_patch
do_spice
do_qemu

echo "All ok!"
