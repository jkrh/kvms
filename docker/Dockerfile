FROM ubuntu:20.04
ARG userid
ARG groupid
ARG username

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y git-core gnupg flex bison build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig
RUN apt-get install -y pip crossbuild-essential-arm64
RUN apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu make ninja-build bsdmainutils libdrm-dev libegl-dev libegl1-mesa-dev libelf-dev libexpat1-dev libgl-dev libgles-dev libglib2.0-dev libglib2.0-dev-bin libglu1-mesa-dev libglvnd-core-dev libglx-dev libgmp-dev libice-dev libmagic-dev libmpc-dev libmpfr-dev libpcre3-dev libpcre2-dev libpixman-1-dev libpng-dev libpopt-dev libpulse-dev libsdl1.2-dev libsdl2-dev libspice-protocol-dev libspice-server-dev libwayland-dev libxau-dev libxinerama-dev libxrandr-dev linux-libc-dev xtrans-dev libstdc++-7-dev libssl-dev git texi2html texinfo rsync gawk bc python sudo wget qemu binfmt-support qemu-user-static libx11-xcb1 libx11-6 libxkbcommon0 libxkbcommon-x11-0 libvulkan-dev libvulkan1 libstdc++6-arm64-cross
RUN apt-get install -y libepoxy0 libvirglrenderer1 meson python3-mako libxdamage-dev libxcb-glx0-dev libx11-xcb-dev libxcb-dri2-0-dev libxcb-dri3-dev libxcb-present-dev libxshmfence-dev llvm libvirglrenderer-dev libaio-dev libepoxy-dev wayland-protocols libwayland-egl-backend-dev
RUN apt-get install -y net-tools iputils-ping iproute2 gdb-multiarch

RUN pip install absl-py && pip install urlfetch

RUN groupadd -g $groupid $username \
 && useradd -m -u $userid -g $groupid $username \
 && echo $username >/root/username \
 && echo "export USER="$username >>/home/$username/.gitconfig

RUN usermod -aG sudo $username

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY gitconfig /home/$username/.gitconfig
RUN chown $userid:$groupid /home/$username/.gitconfig
ENV HOME=/home/$username
ENV USER=$username
ENTRYPOINT chroot --userspec=$(cat /root/username):$(cat /root/username) / /bin/bash -i
