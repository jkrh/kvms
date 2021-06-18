#!/bin/bash

ANDROID_DIR=$1
LOCALIP=$(awk '/32 host/ { print f } {f=$2}' <<< "$(</proc/net/fib_trie)" |grep -v 127.0.0.1)
USER=$(whoami)
VDAGENT="-device virtio-serial-pci -device virtserialport,chardev=spicechannel0,name=spice.0 -chardev spicevmc,id=spicechannel0,name=vdagent"

set -e

[ -z "$ANDROID_DIR" ] && echo "Usage: $0 <android dir>" && exit 1
[ -z "$LOCALIP" ] && LOCALIP="127.0.0.1"
[ -z "$QEMUDIR" ] && QEMUDIR="/usr/bin"
[ -z "$MACHINE" ] && MACHINE="virt"
[ -z "$CPUTYPE" ] && CPUTYPE="host"
[ -z "$AUDIO" ] && AUDIO="-audiodev id=spice,driver=spice"
[ -z "$KERNEL" ] && KERNEL="$ANDROID_DIR/Image"
[ -z "$PORT" ] && PORT=$((2000 + RANDOM % 1000))
[ -z "$NET" ] && NETOPTS="-device e1000,netdev=net0 -netdev user,id=net0,host=192.168.7.1,net=192.168.7.0/24,restrict=off,hostname=guest,hostfwd=tcp:$LOCALIP:$PORT-192.168.7.2:22"
[ -z "$MEM" ] && MEM=2048
[ -z "$SMP" ] && SMP="-smp 4"
[ -z "$SPICEMNT" ] && SPICEMNT="/mnt/spice"
[ -z "$SPICESOCK" ] && SPICESOCK="unix=on,addr=$SPICEMNT/sock/$PORT"
[ -z "$SCREEN" ] && SCREEN="-nographic -device virtio-gpu-pci -spice $SPICESOCK,disable-ticketing=on $VDAGENT"
#SCREEN="-serial mon:stdio -vga std -device ramfb"
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
fi

USB="-device qemu-xhci -device usb-kbd -device usb-tablet"
ROOTFS="-drive format=raw,file=rootfs.img"
USERDATA="-drive format=raw,file=userdata.img"
CACHE="-drive format=raw,file=cache.img"
KERNEL_OPTS="root=/dev/vda rootfstype=ext4 ro init=/init selinux=1 checkreqprot=1 androidboot.selinux=permissive ro.kernel.qemu.gltransport=virtio-gpu console=ttyAMA0 androidboot.hardware=ranchu loglevel=8"
QEMUOPTS="-enable-kvm -cpu ${CPUTYPE},${PROFILE} ${SMP} -M ${MACHINE} -m ${MEM} ${DEBUGOPTS} ${NETOPTS} ${AUDIO}"

echo "Running $QEMUDIR/qemu-system-aarch64 as user $USER"
echo "- Guest ssh access available at $LOCALIP:$PORT"
echo "- Spice server at '$SPICESOCK'"
echo "- Host wlan ip $LOCALIP"
echo "- $PROFILE"

echo $QEMUDIR/qemu-system-aarch64 -kernel $KERNEL $DTB $USB $ROOTFS $USERDATA $CACHE $SCREEN -append "$KERNEL_OPTS" $QEMUOPTS

[ -n "$DEBUG" ] && gdb $QEMUDIR/qemu-system-aarch64 -ex "r -kernel $KERNEL $DTB $USB $ROOTFS $USERDATA $CACHE $SCREEN -append \"$KERNEL_OPTS\" $QEMUOPTS" && exit 0
$QEMUDIR/qemu-system-aarch64 -kernel $KERNEL $DTB $USB $ROOTFS $USERDATA $CACHE $SCREEN -append "$KERNEL_OPTS" $QEMUOPTS
