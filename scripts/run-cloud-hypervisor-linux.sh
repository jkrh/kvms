#!/bin/sh -e

USER=$(whoami)

#
# Arguments and defaults
#
[ -z "$PORT" ] && PORT=$((2000 + RANDOM % 1000))
[ -z "$VMMDIR" ] && VMMDIR="."
[ -z "$KERNEL" ] && KERNEL="./Image"
[ -z "$IMAGE" ] && IMAGE="ubuntu20.qcow2"
[ -z "$VMNAME" ] && VMNAME="vm_$PORT"
[ -z "$TAPGWAY" ] && TAPGWAY="192.168.7.1/24"

usage() {
	echo "$0 -tcp|-unix|-core -image <disk image> -kernel <kernel file> [-hw <hw name>]"
	echo ""
	echo "-hw	Available hw specific configurations:"
	echo "	imxq8mmek_1"
	echo "		- Runs with cpuset 0-3 configuration (a53 cores)"
	echo ""
	echo "	Note: Default configuration (-hw parameter omitted) will work with"
	echo "	most of the supported hardware"
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
	exit 0
}

trap cleanup PWR HUP INT TERM EXIT

for i in "$@"; do
	case $i in
		-help)
			usage
			shift
		;;
		-core)
			CORE="on"
			shift
		;;
		-debug)
			DEBUGOPTS="-S -s"
			shift
		;;
		-name)
			VMNAME=$2
			shift; shift
		;;
		-image)
			IMAGE=$2
			shift; shift
		;;
		-kernel)
			KERNEL=$2
			shift; shift
		;;
		-hw)
			HW=$2
			shift; shift
		;;
		-cpuset)
			CPUSET=$2
			shift; shift
		;;
		-cpumems)
			CPUMEMS=$2
			shift; shift
		;;
	esac
done

#
# Image extract when needed
#
extract KERNEL $KERNEL
extract IMAGE $IMAGE

[ ! -e "$KERNEL" ] && echo "Please provide a kernel image" && usage
[ ! -e "$IMAGE" ] && echo "Please provide a bootable system image image" && usage

#
# Detect network
#
status=0
ip route get 8.8.8.8 2>&1  > /dev/null || status=$?
if [ $status -eq 0 ]; then
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
# Hardware specific configuration
#
if [ -n "$HW" ]; then
	if [ "$HW" = "imx8qmmek_1" ]; then
		CPUSET="0-3"
		CPUMEMS="0"
	fi
fi

#
# GPU and Wayland forwarding
#
if [ -S "$XDG_RUNTIME_DIR/wayland-0" ]; then
	GPUWFW="--gpu --gpu-display width=640,height=480 --wayland-sock $XDG_RUNTIME_DIR/wayland-0"
else
	echo "Wayland server socket not found."
	echo "Wayland forwarding is not enabled."
fi

#
# System configuration
#
if [ "$USER" = "root" ]; then
	[ -d /dev/dri ] && chmod 0666 /dev/dri/render*

	if [ "$CORE" = "on" ]; then
		echo "%e.core.%p" > /proc/sys/kernel/core_pattern
		ulimit -c unlimited
	fi

	status=0
	ip tuntap add mode tap user $USER vnet_hdr vmm_tap 2>&1  > /dev/null || status=$?
	if [ $status -eq 0 ]; then
		sleep 1
		ip addr add $TAPGWAY dev vmm_tap
		ip link set vmm_tap up
		echo 1 > /proc/sys/net/ipv4/ip_forward
		iptables -t nat -A POSTROUTING -o $LOCALIF -j MASQUERADE
		iptables -A FORWARD -i $LOCALIF -o vmm_tap -j ACCEPT
		iptables -A FORWARD -i vmm_tap -o $LOCALIF -j ACCEPT

		#guest side example:
		#sudo ip addr add 192.168.7.2/24 dev enp0s4
		#sudo ip link set enp0s4 up
		#sudo ip route add default via 192.168.7.1
	fi



	if [ -z "$CPUSET" ]; then
		echo "Running default cpuset configuration.";
	else
		if [ -z "$CPUMEMS" ]; then
			echo "Invalid configuration: -cpuset without -cpumems"
		else
			echo "Setting up cpuset.cpus: $CPUSET with cpuset.mems: $CPUMEMS"
			[ ! -d /dev/cpuset ] && mkdir /dev/cpuset
			[ -z "$(mount | grep /dev/cpuset)" ] && mount -t cpuset none /dev/cpuset
			[ ! -d /dev/cpuset/$VMNAME ] && mkdir /dev/cpuset/$VMNAME
			echo $CPUSET > /dev/cpuset/$VMNAME/cpuset.cpus
			echo $CPUMEMS > /dev/cpuset/$VMNAME/cpuset.mems
			echo $$ > /dev/cpuset/$VMNAME/tasks
			echo "Running cpuset $(cat /proc/self/cpuset)"
		fi

	fi
else
	echo "The system configuration may not be up to date and the VM execution may fail."
	echo "Run as the user root if that happens or reconfigure the system manually."
fi

KERNEL_OPTS="rw root=/dev/vda1 selinux=0 nokaslr console=ttyAMA0 loglevel=8"

#
# Machine settings
#
[ -z "$MEM" ] && MEM=1024M
# Finally the qemu invocation with some helper output
#
echo "Running $VMMDIR/cloud-hypervisor-static-aarch64 as user $USER"
echo "- Host ip $LOCALIP"
echo $VMMDIR/cloud-hypervisor-static-aarch64 --cpus boot=4 --disk path=$IMAGE --memory size=$MEM --cmdline "$KERNEL_OPTS" --kernel $KERNEL --serial tty --console off --net tap=vmm_tap

$VMMDIR/cloud-hypervisor-static-aarch64 --cpus boot=4 --disk path=$IMAGE --memory size=$MEM --cmdline "$KERNEL_OPTS" --kernel $KERNEL --serial tty --console off --net tap=vmm_tap

echo "Delete this machine network tap"
ip link delete vmm_tap


