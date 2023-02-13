#!/bin/bash -e

export PATH=$PATH:/usr/sbin

usage() {
	echo "$0 -H <host qcow2 file> -p <VM path on the host> -g <guest qcow2 file"
}

while getopts "h?H:p:g:" opt; do
	case "$opt" in
	h|\?)	usage
		exit 0
		;;
	H)	HOST_IMAGE=$OPTARG
		;;
	p)	HOST_PATH=$OPTARG
		;;
	g)	GUEST_IMAGE=$OPTARG
		;;
  esac
done
HOST_TMP=$(mktemp -d)
if [ ! -f $HOST_IMAGE ]
then
	echo "$HOST_IMAGE does not exist" && exit 1
fi
if [ ! -f $GUEST_IMAGE ]
then
	echo "$GUEST_IMAGE does not exist" && exit 1
fi
if [ ! -f $BASE_DIR/.objs/Image.sign ]
then
	 echo "Signed kernel image does not exist"
	 echo "Please run make sign_guest"
	 exit 1
fi
$BASE_DIR/scripts/qmount.py $HOST_IMAGE $HOST_TMP
ret=$?
if [ $ret -ne 0 ]
then
	exit $ret
fi
mkdir -p $HOST_TMP/$HOST_PATH
echo "copying images to  $HOST_IMAGE:/$HOST_PATH"

cp -u $GUEST_IMAGE $HOST_TMP/$HOST_PATH
cp -u $BASE_DIR/scripts/run-qemu6-linux.sh $HOST_TMP/$HOST_PATH
cp -u $BASE_DIR/buildtools/usr/share/qemu/efi-virtio.rom $HOST_TMP/$HOST_PATH
cp -u $BASE_DIR/.objs/Image.sign $HOST_TMP/$HOST_PATH

echo "You can start the guest on the host:"
echo "cd $HOST_PATH"
echo "sudo run-qemu6-linux.sh"
sync
$BASE_DIR/scripts/qumount.py $HOST_TMP
rm -r $HOST_TMP