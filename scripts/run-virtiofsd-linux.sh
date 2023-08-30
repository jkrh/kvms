#!/bin/sh

USER=$(whoami)

if [ $# != 1 ]; then
	echo "Usage:"
	echo "     1. To install virtiofsd and setup shared dir"
	echo "        $ sudo su -"
	echo "        # cd /home/ubuntu/vm/ubuntu22"
	echo "        # ./run-virtiofsd-linux.sh install"
	echo ""
	echo "     2. To run virtiofsd"
	echo "        # ./run-virtiofsd-linux.sh run"

	exit 0
fi

if [ "$USER" = "root" ]; then
	if [ "$1" = "install" ]; then
		curl https://sh.rustup.rs -sSf | sh -s -- -y
		. ~/.cargo/env
		cargo install virtiofsd
		echo "creating shared dir for guest in /home/ubuntu/shared"
		mkdir /home/ubuntu/shared
		cat > /home/ubuntu/shared/testfile.txt << EOF
hello world!!!
EOF
		chown -R ubuntu.ubuntu /home/ubuntu/shared
	else
		. ~/.cargo/env
		rm -f /tmp/vfsd.sock*
		cd /home/ubuntu
		# use RUST_BACKTRACE=full for debugging virtiofsd
		echo "running virtiofsd.."
		virtiofsd --socket-path=/tmp/vfsd.sock --shared-dir=./shared --announce-submounts --inode-file-handles=mandatory &
		echo "call 'sudo mount -t virtiofs katimfs /mnt' on guest"
	fi
else
	echo "This script is written to be run as root user."
	echo "If you want to run as non-privileged user, check https://gitlab.com/virtio-fs/virtiofsd#running-as-non-privileged-user"
fi
