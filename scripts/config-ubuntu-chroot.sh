#!/system/bin/sh

if [ -n "$ENFORCE" ]; then
	setenforce $ENFORCE
fi
ENFORCE=$(getenforce)
echo "Enforce == $ENFORCE"

mkdir -p /data/vmapps

[ ! -z $1 ] && tar xf $1 -C /data/vmapps

CHROOTDIR=/data/vmapps/ubuntu

set -e

# Due to CONFIG_ANDROID_PARANOID_NETWORK
echo 'APT::Sandbox::User "root";' > $CHROOTDIR/etc/apt/apt.conf.d/01-android-nosandbox
echo "nameserver 8.8.8.8" > $CHROOTDIR/etc/resolv.conf
for MNT in proc sys dev mnt; do mount --rbind /$MNT $CHROOTDIR/$MNT; done

PATH=/usr/bin:/usr/sbin /system/bin/chroot /data/vmapps/ubuntu /bin/bash
