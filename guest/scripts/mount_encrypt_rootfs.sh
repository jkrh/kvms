#!/bin/bash
set -e

usage() {
	echo "$0 -k <key> r <rootfs dir> -o <output dir>"
	echo ""
	echo " Mount encrypted guest rootfs"
}

do_cleanup()
{
	echo cleanup
	${BASE_DIR}/scripts/qumount.py $PLAIN_GUEST || true
	umount  -f /dev/mapper/guestfs || true
	dmsetup remove guestfs || true
	qemu-nbd --disconnect $nbddev || true
	sync || true
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

trap do_cleanup SIGHUP SIGINT SIGTERM

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
echo "key=$KEY"
echo "rootfs=$ROOTFS"
echo "outfile=$OUTFILE"
echo ""

if [ -z "${KEY}" ] ||[ -z "${ROOTFS}" ] || [ -z "${OUTFILE}" ] ; then
	usage
 	exit 1
fi

find_free_nbddev
PLAIN_GUEST=$(mktemp -d)

qemu-nbd --connect=$nbddev $ROOTFS
sleep 1
blks=$(blockdev --getsize ${nbddev}p1)

dmsetup create guestfs --table "0 $blks crypt aes-xts-plain64 ${KEY} 0 ${nbddev}p1 0 1 allow_discards"
sleep 1
mount /dev/mapper/guestfs $OUTFILE

echo done
