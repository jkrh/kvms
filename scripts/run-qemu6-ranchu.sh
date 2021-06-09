#!/bin/bash

ANDROID_DIR=$1
LOCALIP=$(awk '/32 host/ { print f } {f=$2}' <<< "$(</proc/net/fib_trie)" |grep -v 127.0.0.1)
USER=$(whoami)
VDAGENT="-device virtio-serial-pci -device virtserialport,chardev=spicechannel0,name=spice.0 -chardev spicevmc,id=spicechannel0,name=vdagent"

set -e

[ -z "$ANDROID_DIR" ] && echo "Usage: $0 <android dir>" && exit 1
[ -z "$LOCALIP" ] && LOCALIP="127.0.0.1"
[ -z "$QEMUDIR" ] && QEMUDIR="/usr/bin"
[ -z "$MACHINE" ] && MACHINE="ranchu"
[ -z "$CPUTYPE" ] && CPUTYPE="host"
[ -z "$AUDIO" ] && AUDIO="-audiodev id=spice,driver=spice"
[ -z "$KERNEL" ] && KERNEL="$ANDROID_DIR/kernel-ranchu"
[ -z "$PORT" ] && PORT=$((2000 + RANDOM % 1000))
[ -z "$NET" ] && NETOPTS="-device e1000,netdev=net0 -netdev user,id=net0,host=192.168.7.1,net=192.168.7.0/24,restrict=off,hostname=guest,hostfwd=tcp:$LOCALIP:$PORT-192.168.7.2:22"
[ -z "$MEM" ] && MEM=2048
[ -z "$SMP" ] && SMP="-smp 4"
[ -z "$SPICEMNT" ] && SPICEMNT="/mnt/spice"
[ -z "$SPICESOCK" ] && SPICESOCK="unix=on,addr=$SPICEMNT/sock/$PORT"
[ -z "$SCREEN" ] && SCREEN="-nographic -device virtio-gpu-pci -spice $SPICESOCK,disable-ticketing=on $VDAGENT"
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

KERNEL_OPTS="nosmp qemu=1 no_timer_check androidboot.hardware=ranchu androidboot.serialno=EMULATOR29X0X1X0 keep_bootcon console=ttyAMA0 android.qemud=1 android.checkjni=1 qemu.gles=0 qemu.settings.system.screen_off_timeout=2147483647 qemu.opengles.version=196608 qemu.uirenderer=skiagl cma=262M@0-4G loop.max_part=7 androidboot.vbmeta.size=4352 androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.digest=5868bf95c4216908ec7e0c6b9043ad2aecf8749051169d13fab0fae735cddd4c androidboot.boot_devices=a003800.virtio_mmio ramoops.mem_address=0xff018000 ramoops.mem_size=0x10000 memmap=0x10000$0xff018000 qemu.dalvik.vm.heapsize=192m"

USB="-device qemu-xhci -device usb-kbd -device usb-tablet"
INITRD="-initrd $ANDROID_DIR/ramdisk.qcow2"
VENDOR="-drive index=0,if=none,id=vendor,format=qcow2,read-only=on,file=$ANDROID_DIR/vendor-qemu.qcow2 -device virtio-blk-device,drive=vendor"
USERDATA="-drive index=1,if=none,id=userdata,format=qcow2,overlap-check=none,cache=unsafe,l2-cache-size=1048576,file=$ANDROID_DIR/userdata.qcow2 -device virtio-blk-device,drive=userdata"
CACHE="-drive index=2,if=none,id=cache,format=qcow2,overlap-check=none,cache=unsafe,l2-cache-size=1048576,file=$ANDROID_DIR/cache.qcow2 -device virtio-blk-device,drive=cache"
SYSTEM="-drive index=3,if=none,id=system,format=qcow2,file=$ANDROID_DIR/system-qemu.qcow2,read-only=on -device virtio-blk-device,drive=system"
QEMUOPTS="-enable-kvm -cpu ${CPUTYPE},${PROFILE} ${SMP} -M ${MACHINE} -m ${MEM} ${DEBUGOPTS} ${NETOPTS} ${AUDIO}"

echo "Running $QEMUDIR/qemu-system-aarch64 as user $USER"
echo "- Guest ssh access available at $LOCALIP:$PORT"
echo "- Spice server at '$SPICESOCK'"
echo "- Host wlan ip $LOCALIP"
echo "- $PROFILE"

echo $QEMUDIR/qemu-system-aarch64 -kernel $KERNEL $DTB $USB $INITRD $VENDOR $USERDATA $CACHE $SYSTEM $SCREEN -append "$KERNEL_OPTS" $QEMUOPTS

[ -n "$DEBUG" ] && gdb $QEMUDIR/qemu-system-aarch64 -ex "r -kernel $KERNEL $DTB $USB $INITRD $VENDOR $USERDATA $CACHE $SYSTEM $SCREEN -append \"$KERNEL_OPTS\" $QEMUOPTS" && exit 0
$QEMUDIR/qemu-system-aarch64 -kernel $KERNEL $DTB $USB $INITRD $VENDOR $USERDATA $CACHE $SYSTEM $SCREEN -append "$KERNEL_OPTS" $QEMUOPTS
