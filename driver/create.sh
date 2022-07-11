#!/bin/bash

if (($# != 3))
then
    echo "Usage create dev name file"
    exit 1
fi
device=$1
name=$2
file=$3

# Create a key
./hyp_ioctl 5 $name
./hyp_ioctl 7 $file

# Create a crypt device using dmsetup when encryption key is stored in keyring service
dmsetup create $name --table "0 `blockdev --getsize $device` crypt aes-cbc-essiv:sha256 :32:user:hyp:$name 0 $device 0"

mkfs.ext4 /dev/mapper/$name
mkdir -p /mnt/$name
mount /dev/mapper/$2 /mnt/$name
chmod 777  /mnt/$name
