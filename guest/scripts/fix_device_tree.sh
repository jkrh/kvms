#!/bin/bash -e

INITRAMFS_START=0x48008000

usage() {
	echo "$0 -i <input dts> -s <initdr size> | -u"
}

while getopts "h?i:s:" opt; do
	case "$opt" in
	h|\?)	usage
		exit 0
		;;
	i)	INDTS=$OPTARG
		;;
	s)	SIZE=$OPTARG
		;;
   esac
done

LINE1="linux,initrd-start = <$(printf "0x%.8x" $(( $INITRAMFS_START )))>;"
LINE2="linux,initrd-end = <$(printf "0x%.8x" $(( $INITRAMFS_START + $SIZE )))>;"
sed "/chosen /a \ \t\t${LINE1}\n\t\t${LINE2}" $INDTS > enc_$(basename $INDTS)

echo "Done"