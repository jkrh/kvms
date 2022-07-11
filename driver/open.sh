!/bin/bash

if (($# != 3))
then
    echo "Usage create dev name file"
    exit 1
fi
device=$1
name=$2
file=$3

# reada key
./hyp_ioctl 8 $file.keys
./hyp_ioctl 6 $name


# Create a crypt device using dmsetup when encryption key is stored in keyring service
dmsetup create $name --table "0 `blockdev --getsize $devive` crypt aes-cbc-essiv:sha256 :32:user:hyp:$name 0 $devive 0"

mkdir -p /mnt/$name
chmod 777 /mnt/$name
mount /dev/mapper/$2 /mnt/$name
