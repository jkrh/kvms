#!/bin/bash

IMAGE=$1
LOCALIP=$(awk '/32 host/ { print f } {f=$2}' <<< "$(</proc/net/fib_trie)" |grep -v 127.0.0.1)
USER=$(whoami)
VDAGENT="-device virtio-serial-pci -device virtserialport,chardev=spicechannel0,name=spice.0 -chardev spicevmc,id=spicechannel0,name=vdagent"

set -e

[ -z "$IMAGE" ] && echo "Usage: $0 <bootable image>" && exit 1
[ -z "$LOCALIP" ] && LOCALIP="127.0.0.1"
[ -z "$QEMUDIR" ] && QEMUDIR="./"
[ -z "$MACHINE" ] && MACHINE="ranchu"
[ -z "$CPUTYPE" ] && CPUTYPE="host"
[ -z "$AUDIO" ] && AUDIO="-audiodev id=spice,driver=spice"
[ -z "$KERNEL" ] && KERNEL="Image"
[ -z "$PORT" ] && PORT=$((2000 + RANDOM % 1000))
[ -z "$NET" ] && NETOPTS="-device e1000,netdev=net0 -netdev user,id=net0,host=192.168.7.1,net=192.168.7.0/24,restrict=off,hostname=guest,hostfwd=tcp:$LOCALIP:$PORT-192.168.7.2:22"
[ -z "$MEM" ] && MEM=2048
[ -z "$SMP" ] && SMP="-smp 4"
[ -z "$SPICEMNT" ] && SPICEMNT="/mnt/spice"
[ -z "$SPICESOCK" ] && SPICESOCK="unix=on,addr=$SPICEMNT/sock/$PORT"
[ -z "$SCREEN" ] && SCREEN="-nographic -device virtio-gpu-pci -spice $SPICESOCK,disable-ticketing=on $VDAGENT"
[ -n "$PROFILE" ] && PROFILE="pmu=on"
[ -z "$PROFILE" ] && PROFILE="pmu=off"

clean_up() {
	rm -f $SPICEMNT/sock/$PORT
	exit 0
}
trap clean_up SIGHUP SIGINT SIGTERM EXIT

if [ "$USER" = "root" ]; then
	[ ! -d /dev/net ] && mkdir /dev/net
	[ ! -c /dev/net/tun ] && mknod /dev/net/tun c 10 200 && chmod 0666 /dev/net/tun
	[ ! -d $SPICEMNT ] && mkdir -p $SPICEMNT && chmod 0777 $SPICEMNT
	[ -z "$(mount | grep $SPICEMNT)" ] && mount -t tmpfs -o size=1g tmpfs $SPICEMNT
	[ ! -d $SPICEMNT/sock ] && mkdir -p $SPICEMNT/sock && chmod 0777 $SPICEMNT/sock
fi

KERNEL_OPTS="root=/dev/vda console=ttyAMA0 nokaslr loglevel=8 rw ${SYSTEMD_DEBUG}"
USB="-device qemu-xhci -device usb-kbd -device usb-tablet"
DRIVE="-device virtio-blk-device,drive=ubu-sd -drive file=$IMAGE,format=raw,id=ubu-sd,if=none"
QEMUOPTS="-enable-kvm -cpu ${CPUTYPE} ${SMP} -M ${MACHINE} -m ${MEM} ${DEBUGOPTS} ${NETOPTS} ${AUDIO}"

echo "Running $QEMUDIR/qemu-system-aarch64 as user $USER"
echo "- Guest ssh access available at $LOCALIP:$PORT"
echo "- Spice server at '$SPICESOCK'"
echo "- Host wlan ip $LOCALIP"
echo "- $PROFILE"

[ -n "$DEBUG" ] && gdb /usr/bin/qemu-system-aarch64 -ex "r -kernel $KERNEL $DTB $USB $DRIVE $SCREEN -append \"$KERNEL_OPTS\" $QEMUOPTS" && exit 0

qemu-system-aarch64 -kernel $KERNEL $DTB $USB $DRIVE $SCREEN -append "$KERNEL_OPTS" $QEMUOPTS
