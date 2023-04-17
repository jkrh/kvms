#!/bin/bash
set -e

usage() {
	echo "$0 -k <key> r <rootfs dir> -o <output dir>"
	echo ""
	echo " Encrypt guest rootfs"
}

do_cleanup()
{
	${BASE_DIR}/scripts/qumount.py $PLAIN_GUEST || true
	umount  -f /dev/mapper/guestfs || true
	rmdir $PLAIN_GUEST $CIPHER_GUEST || true
	dmsetup remove guestfs || true
	qemu-nbd --disconnect $nbddev || true
	sync || true
}

wait_for_dev() {
	echo "Waiting $1"
	for i in {0..5}
	do
	sleep 1
	if [ -b $1 ] ; then
		return
	fi
	echo "Device $1 does not exist"
	exit 1
	done
}

find_free_nbddev() {
	for i in {0..8}
	do
		if [ ! -b "/dev/nbd${i}p1" ]; then
			nbddev="/dev/nbd${i}"
			return 0
		fi
	done
}

if [ -z "${BASE_DIR}" ]; then
	echo "BASE_DIR is not set. Should point to KVMS base"
	exit 1
fi

trap do_cleanup SIGHUP SIGINT SIGTERM EXIT

while getopts "h?k:r:o:" opt; do
	case "$opt" in
		h|\?)
			usage
			exit 0
		;;
		k)  KEY=$OPTARG
		;;
		r)  ROOTFS=$OPTARG
		;;
		o)  OUTFILE=$OPTARG
		;;
	esac
done

echo ""
echo "$0 using:"
echo "rootfs=$ROOTFS"
echo "outfile=$OUTFILE"
echo ""

if [ -z "${KEY}" ] ||[ -z "${ROOTFS}" ] || [ -z "${OUTFILE}" ] ; then
	usage
 	exit 1
fi
modprobe nbd max_part=8

find_free_nbddev
CIPHER_GUEST=$(mktemp -d)
PLAIN_GUEST=$(mktemp -d)

SIZE=$(qemu-img info ${ROOTFS} | sed  -ne '/virtual size: /p' | \
	sed -ne 's/.*(\([0-9]* bytes\)).*/\1/p' | sed -e 's/ bytes//')

qemu-img create -f qcow2 $OUTFILE $SIZE
qemu-nbd --connect=$nbddev $OUTFILE
parted -a optimal $nbddev mklabel gpt mkpart primary ext4 0% 100%
wait_for_dev ${nbddev}p1

blks=$(blockdev --getsize ${nbddev}p1)

dmsetup create guestfs --table "0 $blks crypt aes-xts-plain64 ${KEY} 0 ${nbddev}p1 0 1 allow_discards"
wait_for_dev /dev/mapper/guestfs
mkfs.ext4 /dev/mapper/guestfs
mount /dev/mapper/guestfs $CIPHER_GUEST
${BASE_DIR}/scripts/qmount.py $ROOTFS $PLAIN_GUEST -r

echo "Copying files to encrypted rootfs (${CIPHER_GUEST})..."
cp -a $PLAIN_GUEST/* $CIPHER_GUEST/
sync
echo done
