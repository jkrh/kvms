#!/bin/bash
set -e

# create guest certificate request

usage() {
        echo "usage:"
        echo "$0 -s <sign_key file> -e <encryption_key file> \\"
        echo " -o <output name>"
        echo ""
        echo "Create guest certificate request file"
}

add_key() {
	local MAGIC=$1
	local ITEM=$2
	local MAX_LEN=$3
	echo -n $MAGIC
	local LEN=$(( ${#ITEM} / 2 ))

	printf "0: %.8x" $(( LEN )) | sed -E 's/0: (..)(..)(..)(..)/0:\4\3\2\1/' | \
         xxd -r
	echo $ITEM | xxd -r -p
	dd if=/dev/zero bs=1 count=$(( MAX_LEN - LEN )) status=none
}

while getopts "h?s:e:o:" opt; do
	case "$opt" in
		h|\?)
			usage
			exit 0
		;;
		s)  SIGN_KEY=$OPTARG
		;;
		e)  ENC_KEY=$OPTARG
		;;
		o)  OUTFILE=$OPTARG
		;;
	esac
done

echo ""
echo "$0 using:"
echo "encryption key=$ENC_KEY"
echo "signatute key=$SIGN_KEY"
echo "outfile=$OUTFILE"
echo ""

if [ -z "${SIGN_KEY}" ] || [ -z "${ENC_KEY}" ] || [ -z "${OUTFILE}" ] ; then
    usage
    echo exit
    exit 1
fi

# add guest encryption public key
add_key SIGN $(cat $SIGN_KEY) 80 > "${OUTFILE}"
add_key ENCR $(cat $ENC_KEY) 80  >> "${OUTFILE}"

