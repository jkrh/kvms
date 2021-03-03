FROM ubuntu:20.04
ARG userid
ARG groupid
ARG username

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y apt-utils gcc-aarch64-linux-gnu g++-aarch64-linux-gnu make ninja-build bsdmainutils libdrm-dev libegl-dev libegl1-mesa-dev libelf-dev libexpat1-dev libgl-dev libgl1-mesa-dev libgles-dev libglib2.0-dev libglib2.0-dev-bin libglu1-mesa-dev libglvnd-core-dev libglx-dev libgmp-dev libice-dev libmagic-dev libmpc-dev libmpfr-dev libpcre3-dev libpcre2-dev libpixman-1-dev libpng-dev libpopt-dev libpulse-dev libsdl1.2-dev libsdl2-dev libspice-protocol-dev libspice-server-dev libwayland-dev libx11-dev libxau-dev libxinerama-dev libxrandr-dev linux-libc-dev xtrans-dev zlib1g-dev libstdc++-7-dev libssl-dev git build-essential texi2html texinfo bison flex rsync gawk bc python

RUN groupadd -g $groupid $username \
 && useradd -m -u $userid -g $groupid $username \
 && echo $username >/root/username \
 && echo "export USER="$username >>/home/$username/.gitconfig

COPY gitconfig /home/$username/.gitconfig
RUN chown $userid:$groupid /home/$username/.gitconfig
ENV HOME=/home/$username
ENV USER=$username
ENTRYPOINT chroot --userspec=$(cat /root/username):$(cat /root/username) / /bin/bash -i
