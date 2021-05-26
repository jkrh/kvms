# work in progress
# Push following files from android aosp (aosp_arm64-eng):
# adb push <aosp build root>/qemu_android/out/target/product/generic_arm64/kernel-ranchu /data/media/vmapps/android/
# adb push <aosp build root>/qemu_android/out/target/product/generic_arm64/vendor-qemu.img /data/media/vmapps/android/
# adb push <aosp build root>/qemu_android/out/target/product/generic_arm64/userdata-qemu.img.qcow2 /data/media/vmapps/android/
# adb push <aosp build root>/out/target/product/generic_arm64/userdata-qemu.img /data/media/vmapps/android/
# adb push <aosp build root>/qemu_android/out/target/product/generic_arm64/cache.img.qcow2 /data/media/vmapps/android/
# adb push <aosp build root>/qemu_android/out/target/product/generic_arm64/cache.img /data/media/vmapps/android/
# adb push <aosp build root>/qemu_android/out/target/product/generic_arm64/system-qemu.img /data/media/vmapps/android/

LOCALIP=$(ifconfig wlan0 | grep "inet addr" | cut -d ":" -f2 | cut -d " " -f1)
USER=$(whoami)
VDAGENT="-device virtio-serial-pci -device virtserialport,chardev=spicechannel0,name=spice.0 -chardev spicevmc,id=spicechannel0,name=vdagent"

[ -z "$LOCALIP" ] && LOCALIP="127.0.0.1"
[ -z "$QEMUDIR" ] && QEMUDIR="./"
[ -z "$MACHINE" ] && MACHINE="-machine type=virt"
[ -z "$CPUTYPE" ] && CPUTYPE="host"
[ -z "$AUDIO" ] && AUDIO="-audiodev id=spice,driver=spice -soundhw hda"
[ -z "$KERNEL" ] && KERNEL="/data/media/vmapps/android/kernel-ranchu"
[ -z "$PORT" ] && PORT=$((2000 + RANDOM % 1000))
[ -z "$NET" ] && NETOPTS="-nic user,id=net0 -netdev user,id=net0,host=192.168.7.1,net=192.168.7.0/24,restrict=off,hostname=guest"
[ -z "$MEM" ] && MEM=3072
[ -z "$SMP" ] && SMP=""
[ -z "$SPICEMNT" ] && SPICEMNT="/mnt/spice"
[ -z "$SPICESOCK" ] && SPICESOCK="unix,addr=$SPICEMNT/sock/$PORT"
[ -z "$SCREEN" ] && SCREEN="-nographic -device virtio-gpu-pci -spice $SPICESOCK,disable-ticketing $VDAGENT"
[ -n "$DEBUG" ] && DEBUGOPTS="-S -s"
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
	mkdir /mnt/media_rw/st5-a
	mount /dev/block/sdg1 /mnt/media_rw/st5-a
fi

KERNEL_OPTS="nosmp qemu=1 no_timer_check androidboot.hardware=ranchu androidboot.serialno=EMULATOR29X0X1X0 keep_bootcon console=ttyAMA0 android.qemud=1 android.checkjni=1 qemu.gles=1 qemu.settings.system.screen_off_timeout=2147483647 qemu.opengles.version=196608 qemu.uirenderer=skiagl cma=262M@0-4G loop.max_part=7 androidboot.vbmeta.size=4352 androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.digest=5868bf95c4216908ec7e0c6b9043ad2aecf8749051169d13fab0fae735cddd4c androidboot.boot_devices=a003800.virtio_mmio ramoops.mem_address=0xff018000 ramoops.mem_size=0x10000 memmap=0x10000$0xff018000 qemu.dalvik.vm.heapsize=192m"

USB="-device qemu-xhci -device usb-kbd -device usb-tablet"
INITRD="-initrd /data/media/vmapps/android/ramdisk.img"
VENDOR="-drive index=0,if=none,id=vendor,format=raw,read-only,file=android/vendor-qemu.img -device virtio-blk-device,drive=vendor"
USERDATA="-drive index=1,if=none,id=userdata,format=qcow2,overlap-check=none,cache=unsafe,l2-cache-size=1048576,file=/data/media/vmapps/android/userdata-qemu.img.qcow2 -device virtio-blk-device,drive=userdata"
CACHE="-drive index=2,if=none,id=cache,format=qcow2,overlap-check=none,cache=unsafe,l2-cache-size=1048576,file=/data/media/vmapps/android/cache.img.qcow2 -device virtio-blk-device,drive=cache"
SYSTEM="-drive index=3,if=none,id=system,format=raw,file=/data/media/vmapps/android/system-qemu.img,read-only -device virtio-blk-device,drive=system"

QEMUOPTS="-enable-kvm -cpu ${CPUTYPE},${PROFILE} ${SMP} ${MACHINE},virtualization=off,secure=off,highmem=off -m ${MEM} ${DEBUGOPTS} ${NETOPTS} ${AUDIO}"

ANDROID="-mem-path /mnt/media_rw/vmdata/ram.img -nodefaults"

echo "Running $QEMUDIR/qemu-system-aarch64 as user $USER"
echo "- Guest ssh access available at $LOCALIP:$PORT"
echo "- Spice server at '$SPICESOCK'"
echo "- Host wlan ip $LOCALIP"
echo "- $PROFILE"

echo $QEMUDIR/qemu-system-aarch64 \
	-kernel $KERNEL \
	$DTB $USB \
	$INITRD \
	$VENDOR \
	$USERDATA \
	$CACHE \
	$SYSTEM \
	$SCREEN \
	-append "$KERNEL_OPTS" \
	$QEMUOPTS

$QEMUDIR/qemu-system-aarch64 \
	-kernel $KERNEL \
	$DTB $USB \
	$INITRD \
	$VENDOR \
	$USERDATA \
	$CACHE \
	$SYSTEM \
	$SCREEN \
	-append "$KERNEL_OPTS" \
	$QEMUOPTS
