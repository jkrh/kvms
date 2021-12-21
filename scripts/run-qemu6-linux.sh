#!/bin/sh -e

USER=$(whoami)

#
# Arguments and defaults
#
[ -z "$PORT" ] && PORT=$((2000 + RANDOM % 1000))
[ -z "$QEMUDIR" ] && QEMUDIR="."
[ -z "$KERNEL" ] && KERNEL="./Image"
[ -z "$IMAGE" ] && IMAGE="ubuntu20.qcow2"
[ -z "$SPICEMNT" ] && SPICEMNT="/mnt/spice"
[ -z "$SPICESOCK" ] && SPICEPORT=$(($PORT+1)) && SPICESOCK="port=$SPICEPORT"

export TMPDIR=$SPICEMNT

usage() {
	echo "$0 -tcp|-unix -image <disk image> -kernel <kernel file>"
	rm -f $SPICESOCK
	exit 1
}

extract() {
	if file $2 | grep -q compressed ; then
		echo "Extracting $1 $2.."
		gunzip $2
		export $1=$(basename $2 .gz)
	fi
}

cleanup() {
	rm -f $SPICESOCK
	exit 0
}

trap cleanup PWR HUP INT TERM EXIT

for i in "$@"; do
	case $i in
		-help)
			usage
			shift
		;;
		-tcp)
			SPICEPORT=$(($PORT+1))
			SPICESOCK="port=$SPICEPORT"
			shift
		;;
		-unix)
			SPICEPORT=$((0))
			SPICESOCK="unix=on,addr=$SPICEMNT/sock/linux$PORT"
			shift
		;;
		-image)
			IMAGE=$2
			shift; shift
		;;
		-kernel)
			KERNEL=$2
			shift; shift
		;;
	esac
done

#
# Image exract when needed
#
extract KERNEL $KERNEL
extract IMAGE $IMAGE

[ ! -e "$KERNEL" ] && echo "Please provide a kernel image" && usage
[ ! -e "$IMAGE" ] && echo "Please provide a bootable system image image" && usage

#
# Detect network
#
ip route get 8.8.8.8 2>&1 > /dev/null
if [ $? -eq 0 ]; then
	LOCALIF=$(ip route get 8.8.8.8 |awk '{print $5}')
	LOCALIP=$(ip route get 8.8.8.8 |awk '{print $7}')
else
	echo "For the VM networking support please enable the network"
	echo "before starting the VMs. Now starting with local networking"
	echo "only."
	LOCALIF="lo"
	LOCALIP="127.0.0.1"
fi

#
# System configuration
#
if [ "$USER" = "root" ]; then
	[ ! -d /dev/net ] && mkdir /dev/net
	[ ! -c /dev/net/tun ] && mknod /dev/net/tun c 10 200 && chmod 0666 /dev/net/tun
	[ ! -d $SPICEMNT ] && mkdir -p $SPICEMNT && chmod 0777 $SPICEMNT
	[ -z "$(mount | grep $SPICEMNT)" ] && mount -t tmpfs -o size=1g tmpfs $SPICEMNT
	[ ! -d $SPICEMNT/sock ] && mkdir -p $SPICEMNT/sock && chmod 0777 $SPICEMNT/sock
	[ -d /dev/dri ] && chmod 0666 /dev/dri/render*

	echo 1 > /proc/sys/net/ipv4/ip_forward
	iptables -t nat -A POSTROUTING -o $LOCALIF -j MASQUERADE
else
	echo "The system configuration may not be up to date and the VM execution may fail."
	echo "Run as the user root if that happens or reconfigure the system manually."
fi

#
# Screen configuration
#
VDAGENT="-device virtio-serial-pci -device virtserialport,chardev=spicechannel0,name=spice.0 -chardev spicevmc,id=spicechannel0,name=vdagent"
SPICEOPTS="$SPICESOCK,disable-ticketing=on,image-compression=off,seamless-migration=on,streaming-video=all,playback-compression=off,disable-agent-file-xfer=off"

#
# Machine settings
#
[ -z "$MACHINE" ] && MACHINE="virt"
[ -z "$MEM" ] && MEM=3096
[ -z "$SMP" ] && SMP="-smp 4"
[ -z "$AUDIO" ] && AUDIO="-audiodev spice,id=spice -soundhw hda"
CPU="-enable-kvm -cpu host,pmu=off"
USB="-device qemu-xhci -device usb-kbd -device usb-tablet"
RNG="-device virtio-rng-pci,id=rng0,max-bytes=1024,period=2000"
BALLOON="-device virtio-balloon-pci,id=balloon0"
DRIVE="-drive file=$IMAGE,format=qcow2,if=none,id=ubu-sd -device virtio-blk-device,drive=ubu-sd"
KERNEL_OPTS="rw root=/dev/vda1 selinux=0 nokaslr console=ttyAMA0 loglevel=8"
QEMUOPTS="${CPU} ${SMP} -M ${MACHINE} -m ${MEM} ${DEBUGOPTS} ${NETOPTS} ${RNG} ${AUDIO} ${BALLOON} ${DEBUG} -L . -portrait"
NETOPTS="-device e1000,netdev=net0 -netdev user,id=net0,host=192.168.7.1,net=192.168.7.0/24,restrict=off,hostname=guest$PORT,hostfwd=tcp:$LOCALIP:$PORT-192.168.7.2:22"
SCREEN="-nographic -device virtio-gpu-pci -spice $SPICEOPTS $VDAGENT"

#
# Finally the qemu invocation with some helper output
#
echo "Running $QEMUDIR/qemu-system-aarch64 as user $USER"
echo "- Guest ssh access available at $LOCALIP:$PORT"
if [ $SPICEPORT -eq 0 ]; then
	echo "- Spice server at 'spice+unix:/$SPICESOCK'"
else
	echo "- Spice server at 'spice://$LOCALIP:$SPICEPORT'"
fi
echo "- Host wlan ip $LOCALIP"

$QEMUDIR/qemu-system-aarch64 -kernel $KERNEL $DRIVE $DTB $USB $PARTITIONS $SCREEN -append "$KERNEL_OPTS" $QEMUOPTS
