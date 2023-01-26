#!/bin/bash

#
# Tested on ubuntu 20+. You need to have qemu-user-static and binfmt-support
# installed.
#

TOOLDIR=$BASE_DIR/buildtools
QEMU_USER=`which qemu-aarch64-static`

#
# Default: dynamic, opengl, spice, virgl, hybris
#

if [ -n "$STATIC" ]; then
echo "Static build"
SPICE="${SPICE:-1}"
OPENGL="${OPENGL:-""}"
SDL="${SDL:-""}"
VIRGL="${VIRGL:-""}"
SSTATIC="--enable-static"
QSTATIC="--disable-libudev --disable-xkbcommon --static"
SHARED_GLAPI="-Dshared-glapi=disabled -Dglx=disabled"
else
echo "Full sysroot build"
SPICE="${SPICE:-1}"
OPENGL="${OPENGL:-1}"
SDL="${SDL:-1}"
VIRGL="${VIRGL:-1}"
SSTATIC=""
QSTATIC=""
SHARED_GLAPI="-Dshared-glapi=enabled -Dglx=gallium-xlib"
fi

if [ -n "$OPENGL" ]; then
echo "OpenGL enabled"
OPENGL="--enable-opengl"
else
echo "OpenGL disabled"
OPENGL="--disable-opengl"
fi

if [ -n "$SPICE" ]; then
echo "Spice enabled"
SPICE="--enable-spice"
else
echo "Spice disabled"
SPICE="--disable-spice"
fi

if [ -n "$SDL" ]; then
echo "SDL enabled"
SDL="--enable-sdl --audio-drv-list=sdl"
else
echo "SDL disabled"
SDL="--disable-sdl --audio-drv-list="
fi

if [ -n "$VIRGL" ]; then
echo "VIRGL enabled"
VIRGL="--enable-virglrenderer"
else
echo "VIRGL disabled"
VIRGL="--disable-virglrenderer"
fi

#
# For time being still compile static with 20.04. There is a libc bug present
# in the 22+ that prevents a large binary static linkage and we can only switch
# to this after this is merged:
# https://sourceware.org/bugzilla/show_bug.cgi?id=29514
#
# That, or we could do a libc PPA. However the signing infrastructure seems
# broken too on arm64 (verified with Guillem Jover) so even that is struggle
# I'm not personally interested in at the moment.
#
if [ -n "$STATIC" ]; then
UBUNTU_BASE=http://cdimage.debian.org/mirror/cdimage.ubuntu.com/ubuntu-base/releases/20.04/release/ubuntu-base-20.04.1-base-arm64.tar.gz
PKGLIST=`cat $BASE_DIR/scripts/package.list.20`
else
UBUNTU_BASE=http://cdimage.debian.org/mirror/cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04-base-arm64.tar.gz
#UBUNTU_BASE=https://cdimage.debian.org/mirror/cdimage.ubuntu.com/ubuntu-base/releases/22.10/release/ubuntu-base-22.10-base-arm64.tar.gz
PKGLIST=`cat $BASE_DIR/scripts/package.list.22`
fi

MESA_VER="${MESA_VER:-"mesa-20.2.6"}"
SPICE_VER="${SPICE_VER:-"spice-0.14.3"}"
UTIL_LINUX_VER=2.37.4

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
export CHROOTDIR=$BASE_DIR/oss/ubuntu

NJOBS=`nproc`
REPO=`which repo`

set -e

do_unmount()
{
	if [[ $(findmnt -M "$1") ]]; then
		sudo umount $1
		if [ $? -ne 0 ]; then
			echo "ERROR: failed to umount $1"
			exit 1
		fi
	fi
}

do_unmount_all()
{
	[ -n "$LEAVE_MOUNTS" ] && echo "leaving bind mounts in place." && exit 0

	echo "Unmount all binding dirs"
	do_unmount $CHROOTDIR/build/qemu
	do_unmount $CHROOTDIR/proc
	do_unmount $CHROOTDIR/dev
}

do_clean()
{
	do_unmount_all
	cd $BASE_DIR/oss/qemu; sudo git clean -xfd || true
}

do_distclean()
{
	do_unmount_all
	cd $BASE_DIR/oss/qemu; sudo git clean -xfd || true
	sudo rm -rf $CHROOTDIR
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
	mkdir -p $CHROOTDIR/build
	if [ -e $CHROOTDIR/bin/bash ]; then
		sudo mount --bind /dev $CHROOTDIR/dev
		sudo mount -t proc none $CHROOTDIR/proc
		return;
	fi

	cd $CHROOTDIR
	wget -c $UBUNTU_BASE
	tar xf `basename $UBUNTU_BASE`
	sudo mount --bind /dev $CHROOTDIR/dev
	sudo mount -t proc none $CHROOTDIR/proc
	echo "nameserver 8.8.8.8" > etc/resolv.conf
	cp $QEMU_USER usr/bin
	sudo chmod a+rwx tmp
	DEBIAN_FRONTEND=noninteractive sudo -E chroot $CHROOTDIR apt-get update
	DEBIAN_FRONTEND=noninteractive sudo -E chroot $CHROOTDIR apt-get -y install $PKGLIST
#	sudo -E chroot $CHROOTDIR update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 10
#	sudo -E chroot $CHROOTDIR update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-10 10
	rm `basename $UBUNTU_BASE`
}

do_spice()
{
	if [ -e $CHROOTDIR/build/$SPICE_VER/server/.libs/libspice-server.a ]; then return; fi

	cd $CHROOTDIR/build
	sudo rm -rf $SPICE_VER
	wget https://www.spice-space.org/download/releases/spice-server/$SPICE_VER.tar.bz2
	tar xf $SPICE_VER.tar.bz2
	sudo -E chroot $CHROOTDIR sh -c "cd /build/$SPICE_VER; ./configure --prefix=/usr --enable-static --disable-celt051 ; make -j$NJOBS ; make install"
}

do_util_linux()
{
	if [ -e $CHROOTDIR/build/util-linux-$UTIL_LINUX_VER/dmesg ]; then return; fi

	cd $CHROOTDIR/build
	wget https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.37/util-linux-$UTIL_LINUX_VER.tar.gz
	tar xf util-linux-$UTIL_LINUX_VER.tar.gz
	sudo -E chroot $CHROOTDIR sh -c "cd /build/util-linux-$UTIL_LINUX_VER; ./configure --enable-static ; make -j$NJOBS ; make install"
}

do_mesa()
{
	if [ -d $CHROOTDIR/build/$MESA_VER/build ]; then return; fi

	cd $CHROOTDIR/build
	wget -c https://archive.mesa3d.org/$MESA_VER.tar.xz
	tar xf $MESA_VER.tar.xz
	sudo -E chroot $CHROOTDIR sh -c "cd /build/$MESA_VER; meson build --prefix /usr/local $MESAGL -Dopengl=true -Dosmesa=gallium -Dgallium-drivers=swrast,freedreno $SHARED_GLAPI ; cd build; meson install"
}

do_qemu()
{
	#
	# Build always
	#
	mkdir -p $CHROOTDIR/build/qemu
	sudo mount --bind $BASE_DIR/oss/qemu $CHROOTDIR/build/qemu
	mkdir -p $CHROOTDIR/build/qemu/build
	cd $CHROOTDIR/build
	if [ ! -e qemu/config.status ]; then
		if [ -n "$STATIC" ]; then
			STATIC_QEMU_LIBS="-L/usr/lib/aarch64-linux-gnu -lgmodule-2.0 -lgobject-2.0 -lgio-2.0 -lglib-2.0 -lspice-server -lpixman-1 -lgmodule-2.0 -lgobject-2.0 -lgio-2.0 -lglib-2.0 -lpthread -lpcre -ljpeg -lm -lffi -lz -lssl -lcrypto -ldl -lopus -lm"
			sudo -E chroot $CHROOTDIR sh -c "cd /build/qemu/build; ../configure --prefix=/usr --target-list=aarch64-softmmu --with-git-submodules=ignore --enable-kvm --extra-cflags=\"-fPIC -fno-stack-protector\" --extra-ldflags='$STATIC_QEMU_LIBS' --audio-drv-list=oss --disable-alsa --disable-pa --disable-pie --disable-vnc $SPICE $OPENGL $SDL $VIRGL $QSTATIC"
		else
			sudo -E chroot $CHROOTDIR sh -c "cd /build/qemu/build; ../configure --prefix=/usr --target-list=aarch64-softmmu --with-git-submodules=ignore --enable-kvm --extra-cflags=\"-I/usr/local/include\" --extra-ldflags=\"-L/usr/local/lib/aarch64-linux-gnu -lgbm\" $SPICE $OPENGL $SDL $VIRGL $QSTATIC"
		fi
	fi
	sudo -E chroot $CHROOTDIR sh -c "cd /build/qemu/build; make -j$NJOBS; make install"
}

do_hybris()
{
	if [ ! -d "$ANDROID_BASE" ]; then return; fi

	cd $CHROOTDIR/build
	sudo rm -rf libhybris
	git clone https://github.com/libhybris/libhybris.git
	./libhybris/utils/extract-headers.sh $ANDROID_BASE   $BASE_DIR/oss/ubuntu/usr/local/android/headers
	sudo -E chroot $CHROOTDIR sh -c "cd /build/libhybris/hybris; ./autogen.sh"
	sudo -E chroot $CHROOTDIR sh -c "cd /build/libhybris/hybris; ./configure --prefix=/usr --enable-arch=arm64 --enable-adreno-quirks --enable-mesa --enable-ubuntu-linker-overrides --enable-wayland --enable-property-cache --with-android-headers=/usr/local/android/headers; make -j$NJOBS; make install"
}

do_host_cvd_package()
{
        HOSTCVDDIR=$BASE_DIR/oss/ubuntu/build/android-cuttlefish
        if [ ! -d "$HOSTCVDDIR" ]; then
                git clone https://github.com/google/android-cuttlefish $HOSTCVDDIR
        fi
        if [ ! -f "$HOSTCVDDIR/cuttlefish-base_*_*64.deb" ]; then
                sudo -E chroot $CHROOTDIR qemu-aarch64-static /bin/bash -c \
                        "cd build/android-cuttlefish; \
                        for dir in base frontend; \
                        do cd \$dir; debuild -i -us -uc -b -d; cd ..; done"
                sudo -E chroot $CHROOTDIR sh -c "cd build/android-cuttlefish; \
                        dpkg -i ./cuttlefish-base_*_*64.deb \
                        || apt-get install -f"
                sudo -E chroot $CHROOTDIR sh -c "cd build/android-cuttlefish; \
                        dpkg -i ./cuttlefish-user_*_*64.deb \
                        || apt-get install -f"
                sudo -E chroot $CHROOTDIR sh -c \
                        "addgroup kvm; addgroup cvdnetwork; addgroup render"
                sudo -E chroot $CHROOTDIR sh -c \
                        "usermod -aG kvm,cvdnetwork,render \$USER"
        fi

}

if [[ "$#" -eq 1 ]] && [[ "$1" == "clean" ]]; then
	do_clean
        exit 0
fi
if [[ "$#" -eq 1 ]] && [[ "$1" == "distclean" ]]; then
	do_distclean
        exit 0
fi

trap do_unmount_all SIGHUP SIGINT SIGTERM EXIT

do_sysroot
do_util_linux
do_spice
[ -z "$STATIC" ] && do_mesa
do_qemu
[ -z "$STATIC" ] && do_hybris
[ -n "$HOSTCVD" ] && do_host_cvd_package
echo "All ok!"
