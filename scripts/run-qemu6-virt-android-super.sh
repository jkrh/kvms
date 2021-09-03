#!/bin/bash

#
# Requirements:
# ----------------------------------------------------------------
# - Android 11 or 12
# - 5.10 android kernel
#   export TARGET_PREBUILT_KERNEL=/path/to/Image
# - Mesa3d mainline driver in external/mesa3d
#   - device/google/cuttlefish/shared/device.mk:
#     +PRODUCT_VENDOR_KERNEL_HEADERS := hardware/virt/kernel-headers
#     +BOARD_VENDOR_KERNEL_MODULES := hardware/virt/kernel-modules/*/*.ko
#     +PRODUCT_PACKAGES += \
#     +       libEGL_mesa \
#     +       libGLESv1_CM_mesa \
#     +       libGLESv2_mesa \
#     +       libgallium_dri \
#     +       libglapi
#     +
#     +PRODUCT_DEFAULT_PROPERTY_OVERRIDES += sys.init_log_level=7
#   - device/google/cuttlefish/vsoc_arm64/BoardConfig.mk
#     +BOARD_MESA3D_USES_MESON_BUILD := true
#     +BOARD_MESA3D_GALLIUM_DRIVERS := virgl
# - Custom shared/config/fstab.f2fs that disables the metadata and the fs encryption
#
# Android build:
# -----------------------------------------------------------------
# . build/envsetup.sh
# lunch aosp_cf_arm64_phone-userdebug --- cuttlefish phone, 64bit arm64
# make -j                             --- build
# launch_cvd -vm_manager qemu_cli     --- to produce the super image, 'composite.img' we use below
#
# Run:
# -----------------------------------------------------------------
# - Copy composite.img and the ramdisk.img to the kernel Image to new launch directory, <android dir>
# - $0 <android dir> <kvms tools dir> <use_kvm>
#

ANDROID_DIR=$1
TOOLDIR=$2
KVM=$3

LOCALIP=$(awk '/32 host/ { print f } {f=$2}' <<< "$(</proc/net/fib_trie)" | grep -v 127.0.0.1 | head -n 1)
USER=$(whoami)
VDAGENT="-device virtio-serial-pci -device virtserialport,chardev=spicechannel0,name=spice.0 -chardev spicevmc,id=spicechannel0,name=vdagent"
#DEBUG="-S -s"

set -e

[ -z "$ANDROID_DIR" ] && echo "Usage: $0 <android dir> <tooldir>" && exit 1
[ -z "$TOOLDIR" ] && echo "Usage: $0 <android dir> <tooldir>" && exit 1
[ -z "$LOCALIP" ] && LOCALIP="127.0.0.1"
[ -z "$TOOLDIR" ] && TOOLDIR="/usr/bin"
[ -z "$MACHINE" ] && MACHINE="virt"
[ -z "$AUDIO" ] && AUDIO="-audiodev id=spice,driver=spice"
[ -z "$KERNEL" ] && KERNEL="$ANDROID_DIR/Image"
[ -z "$PORT" ] && PORT=$((2000 + RANDOM % 1000))
[ -z "$NET" ] && NETOPTS="-device e1000,netdev=net0 -netdev user,id=net0,host=192.168.7.1,net=192.168.7.0/24,restrict=off,hostname=guest,hostfwd=tcp:$LOCALIP:$PORT-192.168.7.2:22"
[ -z "$MEM" ] && MEM=2048
[ -z "$SMP" ] && SMP="-smp 4"
[ -z "$SPICEMNT" ] && SPICEMNT="/mnt/spice"
[ -z "$SPICESOCK" ] && SPICESOCK="unix=on,addr=$SPICEMNT/sock/$PORT"
[ -z "$SCREEN" ] && SCREEN="-serial mon:stdio -device virtio-gpu-gl-pci,id=gpu0 -display egl-headless,gl=on -spice $SPICESOCK,disable-ticketing=on,image-compression=off,seamless-migration=on $VDAGENT"
[ -n "$PROFILE" ] && PROFILE="pmu=on"
[ -z "$PROFILE" ] && PROFILE="pmu=off"

cleanup() {
	rm -f $SPICEMNT/sock/$PORT
	exit 0
}
trap cleanup SIGHUP SIGINT SIGTERM EXIT

if [ "$USER" = "root" ]; then
	[ ! -d /dev/net ] && mkdir /dev/net
	[ ! -c /dev/net/tun ] && mknod /dev/net/tun c 10 200 && chmod 0666 /dev/net/tun
	[ ! -d $SPICEMNT ] && mkdir -p $SPICEMNT && chmod 0777 $SPICEMNT
	[ -z "$(mount | grep $SPICEMNT)" ] && mount -t tmpfs -o size=1g tmpfs $SPICEMNT
	[ ! -d $SPICEMNT/sock ] && mkdir -p $SPICEMNT/sock && chmod 0777 $SPICEMNT/sock
	[ -d /dev/dri ] && chmod 0666 /dev/dri/render*
fi

USB="-device qemu-xhci -device usb-kbd -device usb-tablet"
RNG="-device virtio-rng-pci,id=rng0,max-bytes=1024,period=2000"
BALLOON="-device virtio-balloon-pci,id=balloon0"

INITRD="-initrd ${ANDROID_DIR}/ramdisk.img"
SUPER="-drive file=${ANDROID_DIR}/composite.img,format=raw"
PARTITIONS="$INITRD $SUPER"

KERNEL_OPTS="ro selinux=0 nokaslr console=ttyAMA0 loglevel=8 androidboot.boot_devices=4010000000.pcie androidboot.fstab_suffix=f2fs androidboot.slot_suffix=_a androidboot.hardware.hwcomposer=drm_minigbm androidboot.selinux=permissive hw.gpu.mode=mesa ro.kernel.qemu.gltransport=virtio-gpu androidboot.hardware=cutf_cvm androidboot.hardware.gltransport=virtio-gpu androidboot.hardware.vulkan=pastel androidboot.hardware.egl=mesa androidboot.hardware.gralloc=minigbm androidboot.hardware.hwcomposer=drm_minigbm androidboot.lcd_density=160"

if [ -z "$KVM" ]; then
CPU="-cpu max,${PROFILE} "
else
CPU="-enable-kvm -cpu host,${PROFILE}"
fi
QEMUOPTS="${CPU} ${SMP} -M ${MACHINE} -m ${MEM} ${DEBUGOPTS} ${NETOPTS} ${RNG} ${AUDIO} ${BALLOON} ${DEBUG}"

echo "Running $TOOLDIR/qemu-system-aarch64 as user $USER"
echo "- Guest ssh access available at $LOCALIP:$PORT"
echo "- Spice server at '$SPICESOCK'"
echo "- Host wlan ip $LOCALIP"
echo "- $PROFILE"

echo $TOOLDIR/qemu-system-aarch64 -kernel $KERNEL $DTB $USB $PARTITIONS $SCREEN -append "$KERNEL_OPTS" $QEMUOPTS

#[ -n "$DEBUG" ] && gdb $TOOLDIR/qemu-system-aarch64 -ex "r -kernel $KERNEL $DTB $USB $PARTITIONS $SCREEN -append \"$KERNEL_OPTS\" $QEMUOPTS" && exit 0
$TOOLDIR/qemu-system-aarch64 -kernel $KERNEL $DTB $USB $PARTITIONS $SCREEN -append "$KERNEL_OPTS" $QEMUOPTS
