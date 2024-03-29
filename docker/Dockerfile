FROM ubuntu:22.04
ARG userid
ARG groupid
ARG username

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y gcc-multilib g++-multilib
RUN apt-get update && apt-get install -y git-core gnupg flex bison \
build-essential zip curl zlib1g-dev libc6-dev-i386 lib32ncurses5-dev \
x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils \
xsltproc unzip fontconfig pip crossbuild-essential-arm64 \
gcc-aarch64-linux-gnu g++-aarch64-linux-gnu make ninja-build \
bsdmainutils libdrm-dev libegl-dev libegl1-mesa-dev libelf-dev \
libexpat1-dev libgl-dev libgles-dev libglib2.0-dev libglib2.0-dev-bin \
libglu1-mesa-dev libglvnd-core-dev libglx-dev libgmp-dev libice-dev \
libmagic-dev libmpc-dev libmpfr-dev libpcre3-dev libpcre2-dev \
libpixman-1-dev libpng-dev libpopt-dev libpulse-dev libsdl1.2-dev \
libsdl2-dev libspice-protocol-dev libspice-server-dev libwayland-dev \
libxau-dev libxinerama-dev libxrandr-dev linux-libc-dev xtrans-dev \
libssl-dev git texi2html texinfo rsync gawk bc python2 sudo wget qemu \
binfmt-support qemu-user-static libx11-xcb1 libx11-6 libxkbcommon0 \
libxkbcommon-x11-0 libvulkan-dev libvulkan1 libvdeplug2 libepoxy0 \
libvirglrenderer1 meson python3-mako python-is-python3 libxdamage-dev \
libxcb-glx0-dev libx11-xcb-dev libxcb-dri2-0-dev libxcb-dri3-dev \
libxcb-present-dev libxshmfence-dev llvm libvirglrenderer-dev \
libaio-dev libepoxy-dev wayland-protocols libwayland-egl-backend-dev \
net-tools iputils-ping iproute2 gdb-multiarch sshpass \
device-tree-compiler glslang-tools libxcb-shm0-dev doxygen graphviz \
texlive-latex-base texlive-fonts-recommended texlive-latex-extra kmod \
qemu-utils parted cpio xxd zstd udev

RUN pip install absl-py && pip install urlfetch

# Allow choosing a specific openssl version
ARG OPENSSL
RUN if [ -n "$OPENSSL" ] ; then cd /tmp \
&& wget https://www.openssl.org/source/${OPENSSL}.tar.gz \
&& tar -xvf ${OPENSSL}.tar.gz \
&& cd /tmp/${OPENSSL} && ./config shared -Wl,-rpath=/usr/local/ssl/lib --prefix=/usr/local/ssl \
&& make -j 4 && make install \
&& mv /usr/bin/openssl /usr/bin/openssl.old && ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl; fi

RUN groupadd -g $groupid $username \
 && useradd -m -u $userid -g $groupid $username \
 && echo $username >/root/username

RUN usermod -aG sudo $username

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY gitconfig /home/$username/.gitconfig
RUN chown $userid:$groupid /home/$username/.gitconfig
ENV HOME=/home/$username
ENV USER=$username

# Install Rust
USER $username
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH=$HOME/.cargo/bin:$PATH
#RUN rustup install nightly-x86_64-unknown-linux-gnu
#RUN rustup default nightly
RUN rustup target add aarch64-unknown-linux-gnu
RUN rustup toolchain install --force-non-host stable-aarch64-unknown-linux-gnu
RUN bash -c 'echo -e "[target.aarch64-unknown-linux-gnu]\nlinker = \"aarch64-linux-gnu-gcc\"" >> $HOME/.cargo/config'
RUN cargo install cargo-binutils
RUN rustup component add llvm-tools-preview
RUN cd /tmp && git clone https://github.com/eqrion/cbindgen.git
RUN cargo install --force cbindgen

USER root
ENTRYPOINT chroot --userspec=$(cat /root/username):$(cat /root/username) / /bin/bash -i
