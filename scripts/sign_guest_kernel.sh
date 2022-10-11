#!/bin/bash
set -e
# calculate signature over integrity check loader and kernel image
SIGN_VERSION=0x0100
usage() {
	echo "$0 -p <private_key -l <ic_loader binary> -i <guest id>  -k <kernel> -o <output name>"
	echo ""
	echo "  Create kernel image signature file"
}

while getopts "h?p:l:i:k:a:o:" opt; do
	case "$opt" in
		h|\?)
			usage
			exit 0
		;;
		p)  PRIV_KEY=$OPTARG
		;;
		i)  GUESTID=$OPTARG
		;;
		l)  ICLOADER=$OPTARG
		;;
		k)  KERNEL=$OPTARG
		;;
		o)  OUTPUT=$OPTARG
		;;
	esac
done

echo ""
echo "$0 using:"
echo "key=$PRIV_KEY"
echo "ic_loader=$ICLOADER"
echo "guest_id=$GUESTID"
echo "kernel=$KERNEL"
echo "output=$OUTPUT"
echo ""

if [ -z "${PRIV_KEY}" ] || [ -z "${ICLOADER}" ] || [ -z "${KERNEL}" ] || [ -z "${OUTPUT}" ] ; then
    usage
    echo exit
    exit 1
fi

KERNEL_LEN=$(stat -c"%s" $KERNEL)
#add zeros to end of image so that its size is page multiple
PADS=$(( 4096 - $KERNEL_LEN % 4096))
cp ${KERNEL}  ${OUTPUT}
dd if=/dev/zero of=${OUTPUT} bs=$PADS count=1 oflag=append conv=notrunc > /dev/null 2>&1

KERNEL_LEN=$(stat -c"%s" $OUTPUT)
# add loader image so that it starts on begin of page
cat ${ICLOADER} >> ${OUTPUT}
printf "0: %.8x" $(( $SIGN_VERSION )) | sed -E 's/0: (..)(..)(..)(..)/0:\4\3\2\1/' | xxd -r >> ${OUTPUT}

# save first 4 bytes of kernel image to sign data area
dd if=${KERNEL} of=${OUTPUT} bs=4 count=1 oflag=append conv=notrunc > /dev/null 2>&1

# add guest id to data area
# store guest id
echo -n ${GUESTID} >> ${OUTPUT}

dd if=/dev/zero of=${OUTPUT} bs=$(( 16 - ${#GUESTID} )) count=1 oflag=append conv=notrunc > /dev/null 2>&1

if [ "$KERNEL_LEN" -gt $((16#04000000)) ]; then
	echo Too large image
	exit 1
fi
# modifý kernel image first bytes to brach to iclodaer
# bl ic_loader
printf "0: %.8x" $(( $KERNEL_LEN / 4  + 0x94000000)) | sed -E 's/0: (..)(..)(..)(..)/0:\4\3\2\1/' | xxd -r | \
dd  bs=4  count=1 of=${OUTPUT}  conv=notrunc > /dev/null 2>&1
TMPFILE=$(mktemp)
openssl dgst -sha256 -sign ${PRIV_KEY} ${OUTPUT} > ${TMPFILE}
cat ${TMPFILE} >> ${OUTPUT}
rm ${TMPFILE}
echo Signature OK
