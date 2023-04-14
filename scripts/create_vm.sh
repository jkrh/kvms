#!/bin/bash -e

export PATH=$PATH:/usr/sbin

usage() {
	echo "$0 -H <host qcow2 file> -p <VM path on the host> "
}
do_cleanup() {
	sudo ${BASE_DIR}/scripts/qumount.py  $HOST_TMP || true
	sync || true
}

if [ -z "${BASE_DIR}" ]; then
	echo "BASE_DIR is not set. Should point to KVMS base"
	exit 1
fi

trap do_cleanup SIGHUP SIGINT SIGTERM EXIT

while getopts "h?H:p:" opt; do
	case "$opt" in
	h|\?)	usage
		exit 0
		;;
	H)	HOST_IMAGE=$OPTARG
		;;
	p)	HOST_PATH=$OPTARG
		;;
  esac
done

HOST_TMP=$(mktemp -d)
if [ ! -f $HOST_IMAGE ]; then
	echo "$HOST_IMAGE does not exist" && exit 1
fi

$BASE_DIR/scripts/qmount.py $HOST_IMAGE $HOST_TMP

mkdir -p $HOST_TMP/$HOST_PATH
echo "copying images to  $HOST_IMAGE:/$HOST_PATH"

cp -u $BASE_DIR/scripts/run-qemu6-linux.sh $HOST_TMP/$HOST_PATH/
cp -u $BASE_DIR/buildtools/usr/share/qemu/efi-virtio.rom $HOST_TMP/$HOST_PATH/

if [ -n "${KIC_ENABLE}" ]; then
	cp $BASE_DIR/guest/images/Image.sign $HOST_TMP/$HOST_PATH/
	if [ -n "${ENCRYPTED_ROOTFS}" ]; then
		cp -u $BASE_DIR/guest/images/ubuntu.enc.qcow2 $HOST_TMP/$HOST_PATH/
		cp $BASE_DIR/guest/images/initrd $HOST_TMP/$HOST_PATH/
		echo "export ENCRYPTED_ROOTFS=1" > $HOST_TMP/$HOST_PATH/env.sh
		echo "export IMAGE=ubuntu.enc.qcow2" >> $HOST_TMP/$HOST_PATH/env.sh
		echo "export KERNEL=Image.sign" >> $HOST_TMP/$HOST_PATH/env.sh
		chmod u+x $HOST_TMP/$HOST_PATH/env.sh

	else
		cp -u $BASE_DIR/guest/images/ubuntuguest.qcow2 $HOST_TMP/$HOST_PATH/
	fi
else
	cp $BASE_DIR/guest/images/Image $HOST_TMP/$HOST_PATH/
	echo " " > $HOST_TMP/$HOST_PATH/env.sh
	chmod u+x $HOST_TMP/$HOST_PATH/env.sh
fi
sync
