#!/bin/bash -e

usage() {
	echo "$0 -r <plain rootfs file> -o <output> "
}

do_cleanup()
{
	sudo ${BASE_DIR}/scripts/qumount.py $GUEST_TMP || true
	sync || true
}

if [ -z "${BASE_DIR}" ]; then
	echo "BASE_DIR is not set. Should point to KVMS base"
	exit 1
fi

trap do_cleanup SIGHUP SIGINT SIGTERM EXIT

while getopts "h?r:o:" opt; do
	case "$opt" in
	h|\?)	usage
		exit 0
		;;
	r)	GUEST_ROOT=$OPTARG
		;;
	o)	OUT=$OPTARG
		;;
	esac
done

GUEST_TMP=$(mktemp -d)
INITRD_TMP=$(mktemp -d)
echo "original guest root $GUEST_ROOT"
echo "output $OUT"

sudo ${BASE_DIR}/scripts/qmount.py $GUEST_ROOT $GUEST_TMP
mkdir --p ${INITRD_TMP}/{dev,etc,usr/bin,usr/sbin,usr/lib/aarch64-linux-gnu,proc,sbin,sys}

input="${BASE_DIR}/guest/scripts/files"
while read -r line
do
	echo "cp -a ${GUEST_TMP}/$line $(dirname ${INITRD_TMP}/$line)"
	cp -a ${GUEST_TMP}/$line* $(dirname ${INITRD_TMP}/$line)
done < "$input"

cp src/derivekey ${INITRD_TMP}/usr/bin/
cp src/init ${INITRD_TMP}/

cd ${INITRD_TMP}
ln -s usr/bin bin
ln -s usr/lib lib

find . -print0 | cpio --null --create --verbose --format=newc | zstd > ${OUT}
echo Done