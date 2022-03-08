#!/bin/bash

set -e

if [ -z "$FULL_CLEAN" ]; then
  FULL_CLEAN="false"
fi
if [ -z "$CLEAN" ]; then
  CLEAN="true"
fi

KERNEL_PATCH="patches/host/virt/0001-KVM-external-hypervisor-5.6-kernel-baseport.patch"
QEMU_PATCH="patches/qemu-compilation.patch"

CORES=8
if [ "$(which nproc)" ]; then
  CORES="$(nproc)"
fi

# export variables for hyp and qemu
# TODO: add support to other platforms, these parameters should be given
# as script parameters
export KERNEL_DIR="$(pwd)/linux"
export PLATFORM="virt"

# add tools to path
PATH=$(pwd)/buildtools/bin:"$PATH"

function title()
{
  echo ""
  echo "#########################"
  echo " module-compile: $1 "
  echo "#########################"
  echo ""
}

function error()
{
  echo "ERROR: $1"
  exit 1
}

function clean_full()
{
  if [ "$FULL_CLEAN" = "true" ]; then
    title "clean full" \
    && rm -rf linux \
    && rm -rf qemu \
    && git reset --hard \
    && git clean -fdx
  fi
}

function check_tools()
{
  title "check tools"

  make -j"$CORES" tools

  if [ ! "$(which pbzip2)" ]; then
    error "pbzip2 missing: sudo apt install pbzip2"
  fi

  if [ ! "$(which sshpass)" ]; then
    error "sshpass missing: sudo apt install sshpass"
  fi

  if  ! ldconfig -p | grep -q libcapstone; then
    error "libcapstone missing: sudo apt install libcapstone-dev"
  fi

  if ! ldconfig -p | grep -q libglib; then
    error "libglib missing: sudo apt install libglib2.0-dev"
  fi

  if ! ldconfig -p | grep -q libpixman; then
    error "libpixman missing: sudo apt install libpixman-1-dev"
  fi
}

function compile_kernel()
{
  if [ ! -f linux/Makefile ]; then
    title "clone kernel" \
    && rm -rf linux \
    && git clone https://github.com/torvalds/linux.git \
    && cd linux \
    && git checkout 4a267aa7 \
    && cd ..
  fi

  if [ "$CLEAN" = "true" ]; then
    title "clean kernel sources" \
    && cd linux \
    && git reset --hard \
    && git clean -fdx \
    && cd ..

    # clean kernel
    cd linux \
    && make clean && make mrproper \
    && cd ..
  fi

  if patch -d linux --dry-run -N -p1 --silent < "$KERNEL_PATCH" > /dev/null 2>&1; then
    title "apply kvm patch" \
    && cd linux \
    && git apply ../"$KERNEL_PATCH" \
    && cd ..
  fi

  title "compile kernel"
  cd linux \
  && make -j"$CORES" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig Image modules \
  && cd ..
}

function compile_hyp()
{
  if [ "$CLEAN" = "true" ]; then
    title "clean hyp" \
    && make clean
  fi

  title "compile hyp" \
  && make DEBUG=1 -j"$CORES"
}

function compile_qemu()
{
  # clone qemu TODO: do we want to have this as submodule
  if [ ! -f qemu/Makefile ]; then
    title "clone qemu" \
    && rm -rf qemu \
    && git clone https://github.com/qemu/qemu.git -b stable-5.0
  fi

  # clean qemu
  if [ "$CLEAN" = "true" ]; then
    title "clean qemu" \
    && cd qemu \
    && make clean \
    && cd ..
  fi

  if patch -d qemu --dry-run -N -p1 --silent < "$QEMU_PATCH" > /dev/null 2>&1; then
    title "apply qemu compilation patch" \
    && cd qemu \
    && git apply ../"$QEMU_PATCH" \
    && cd ..
  fi

  title "compile qemu" \
  && cd qemu \
  && mkdir -p build \
  && cd build \
  && ../configure --prefix=/usr/local --prefix=qemu/build/pc-bios --target-list=aarch64-softmmu --enable-modules \
  && make -j"$CORES" \
  && cd ../..
}

function usage()
{
  echo "===================================================================="
  echo "  $(basename $0) all      # build all "
  echo "  $(basename $0) kernel   # build kernel"
  echo "  $(basename $0) qemu     # build qemu"
  echo "  $(basename $0) hyp      # build hypervisor"
  echo ""
  echo "  CLEAN=false/true $(basename $0)        # clean or not"
  echo "  FULL_CLEAN=false/true $(basename $0)   # reset, remove or not"
  echo "===================================================================="
}

while (( "$#" )); do
  case "$1" in
    --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*|--*=)
      echo "Error: Unsupported flag $1" >&2
      exit 1
      ;;
    *)
      PARAMS="$PARAMS $1"
      shift
      ;;
  esac
done

if [ -z "$PARAMS" ]; then
  PARAMS=all
fi

check_tools

for param in $PARAMS; do
  case $param in
    all)
      clean_full
      compile_kernel
      compile_hyp
      compile_qemu
      ;;
    kernel)
      compile_kernel
      ;;
    hyp)
      compile_hyp
      ;;
    qemu)
      compile_qemu
      ;;
    *)
      usage
      exit -1
      ;;
  esac
done
