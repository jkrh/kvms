#!/bin/bash
set -e
# calculate signatures over guest authenticated data, kernel image, initrd file
# and device tree

SIGN_VERSION=0x0300

usage() {
	echo "usage:"
	echo "$0 -p <private_key -g <guest id>  -k <kernel> -d <dtb load address> \\"
	echo "-D <dtb file> -i <inittd load address> -I <inittŕd file> -c <guest certificate> \\"
	echo "-o <output name>"
	echo ""
	echo "  Create kernel image signature file"
}

add_hdr()
{
	local MACIG
	local FLAGS
	local OFFSET
	local LOAD
	local SIZE
	local FILE=$5

	if [ -n "$FILE" ] ; then
		MACIG=$1
		FLAGS=$2
		OFFSET=$3
		LOAD=$4
		SIZE=$(stat -c"%s" "$FILE")
	else
		MACIG="\0\0\0\0"
		FLAGS=0
		OFFSET=0
		LOAD=0
		SIZE=0
	fi

	# magig
	echo -ne "$MACIG"
	# flags
	printf "0: %.8x" $(( "$FLAGS" )) | sed -E 's/0: (..)(..)(..)(..)/0:\4\3\2\1/' | xxd -r
	#size
	printf "0: %.8x" $(( $SIZE)) | \
		sed -E 's/0: (..)(..)(..)(..)/0:\4\3\2\1/' | xxd -r
	#offset
	printf "0: %.8x" $(( $OFFSET )) | \
		sed -E 's/0: (..)(..)(..)(..)/0:\4\3\2\1/' | xxd -r
	#load_address
	printf "0: %.16x" $(( $LOAD)) | \
		sed -E 's/0: (..)(..)(..)(..)(..)(..)(..)(..)/0:\8\7\6\5\4\3\2\1/'  | xxd -r

	if [ "$SIZE" -ne 0 ] ; then
		cat "$5" | openssl dgst -sha256 --binary
	else
		echo -n ""  | openssl dgst -sha256 --binary
	fi
}

while getopts "h?p:g:k:d:D:i:I:o:c:" opt; do
	case "$opt" in
	h|\?)	-D "${DTB_FILE}" -d "$(DTB_ADDR)"

		usage
		exit 0
	;;
	p)  PRIV_KEY=$OPTARG
	;;
	g)  GUESTID=$OPTARG
	;;
	k)  KERNEL=$OPTARG
	;;
	d)  DTB_ADDR=$OPTARG
	;;
	D)  DTB_FILE=$OPTARG
	;;
	i)  INITRD_ADDR=$OPTARG
	;;
	I)  INITRD_FILE=$OPTARG
	;;
	c)  GUEST_CERT=$OPTARG
	;;
	o)  OUTFILE=$OPTARG
	;;
	esac
done

echo "$0 using:"
echo "key=$PRIV_KEY"
echo "guest_id=$GUESTID"
echo "kernel=$KERNEL"
echo "dtb file=$DTB_FILE"
echo "dtb load address=$DTB_ADDR"
echo "initrd file=$INITRD_FILE"
echo "initrd load address=$INITRD_ADDR"
echo "guest pub key=$GUEST_PUB"
echo ""

if [ -z "${PRIV_KEY}" ] || [ -z "${KERNEL}" ] || [ -z "${OUTFILE}" ] ; then
    usage
    echo exit
    exit 1
fi
KERNEL_LEN=$(stat -c"%s" "$KERNEL")

if [ -z "$DTB_FILE" ]; then
	DTB_LEN=0
else
	DTB_LEN=$(stat -c"%s" "${DTB_FILE}")
fi

DTB_OFFSET=$(( KERNEL_LEN  + 4096))
INIT_OFFSET=$(( DTB_OFFSET + DTB_LEN ))

# start to buils output image
echo -n "SIGN" > "${OUTFILE}"
printf "0: %.8x" $(( $SIGN_VERSION )) | \
	sed -E 's/0: (..)(..)(..)(..)/0:\4\3\2\1/' | xxd -r >> "${OUTFILE}"

#add guest certificate
cat "$GUEST_CERT" >> "$OUTFILE"
CERT_LEN=$(stat -c"%s" "${GUEST_CERT}")
dd if=/dev/zero of=${OUTFILE} bs=$(( 264 - CERT_LEN )) count=1 oflag=append \
	conv=notrunc status=none

#add loader data
add_hdr "KRNL" 0 0 0 "$KERNEL" >> "$OUTFILE"
add_hdr "DEVT" 0x18 $DTB_OFFSET "$DTB_ADDR" "${DTB_FILE}" >> "$OUTFILE"
add_hdr "INRD" 0x08 $INIT_OFFSET "$INITRD_ADDR" "${INITRD_FILE}" >> "$OUTFILE"

# add guest id
echo -n ${GUESTID} >> ${OUTFILE}
dd if=/dev/zero of=${OUTFILE} bs=$(( 16 - ${#GUESTID} )) count=1 oflag=append \
	conv=notrunc status=none

# add signature
cat  "${OUTFILE}" | openssl dgst -sha256
cat  "${OUTFILE}" | openssl dgst -sha256 -sign "${PRIV_KEY}" >> "${OUTFILE}"

# add zeros so that size id 4096 bytes
LEN=$(stat -c"%s" "${OUTFILE}")
PADS=$(( 4096 - $LEN % 4096 ))
dd if=/dev/zero of="${OUTFILE}" bs=$PADS count=1 oflag=append conv=notrunc \
	status=none
# Guest Authenticated data page is ready

# add kernel image. The first page is moved to end of it
dd if="${KERNEL}" of="${OUTFILE}" ibs=4096 count=$(( $KERNEL_LEN / 4096 )) \
	skip=1 oflag=append conv=notrunc status=none
dd if="${KERNEL}" of="${OUTFILE}" bs=4096 count=1 oflag=append \
	conv=notrunc status=none

if [ -n "$DTB_FILE" ]; then
	# add device three file if it is defined
	cat "$DTB_FILE" >>  "${OUTFILE}"
fi
if [ -n "$INITRD_FILE" ]; then
	# add initrd file if is is defined
	cat "${INITRD_FILE}" >> "${OUTFILE}"
fi

echo Signature file "${OUTFILE}" is ready
exit 0
