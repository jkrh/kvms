#!/bin/bash
set -e
# Return derived key

usage() {
	echo "$0 -p <our private key> -s <salt>"
	echo ""
	echo "Return derived key"
}

while getopts "h?p:s:" opt; do
	case "$opt" in
		h|\?)
			usage
			exit 1
		;;
		p)  PRIV=$OPTARG
		;;
		s) SALT=$OPTARG
		;;
	esac
done

if [ -z "${PRIV}" ] ; then
    usage
    echo exit
    exit 1
fi

PEER=$BASE_DIR/core/keys/encryption_pub.pem
SHARED_SECRET=$(openssl pkeyutl -derive -inkey ${PRIV} -peerkey ${PEER} | xxd -p -c 32)
openssl kdf -binary -keylen 32 -kdfopt digest:sha256 -kdfopt hexkey:${SHARED_SECRET} -kdfopt salt:$SALT HKDF | xxd -p -c 32
