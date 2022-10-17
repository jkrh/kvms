#!/bin/bash

# Script used to compare kernel version and patch used in previous CI build.
# If a new kernel version or patch is used in CI build, scripts/update_kernel_to_ubuntu_VMs.sh will be executed.
# The script will also remove the previous directory where kernel was updated (linux-<kernel version>) from workspace,
# if a new kernel version is used in the current CI build.

# Variables

PRE_PATCH_DIR=previous_kernel
PRE_PATCH_INFO=info

# Functions

usage() {
  echo "$0 -i <VM image> -k <kernel version> -p <patch file> [ -d <info directory> -f <info file name> ]"
  echo ""
  echo "Example:"
  echo "  $0 -i /img/ubuntu20-host.qcow2 -k 5.10.130 -p patches/guest/0001-kvm-encrypted-memory-draft-for-arm64-development.patch"
  echo ""
  echo "  Compares given kernel version and patch to ones used in previous CI build. If new version or patch is used in the build,"
  echo "  builds patched kernel, installs modules to VMs and copies the resulting Image to current workspace."
  echo "  After succesful kernel update, patch file will be stored to the info directory"
  echo "  and info file inside it will be updated with the used kernel version and the stored patch file path."
  echo "  If a new kernel version is used, the old dir with patched kernel sources (linux-<kernel version>) will be also removed."
  echo ""
  echo "  default info directory: $PRE_PATCH_DIR (can be overwritten by option -d)."
  echo "  default info file name: $PRE_PATCH_INFO (can be overwritten by option -f)."
}

update_kernel() {
  sudo modprobe nbd max_part=8
  sudo scripts/update_kernel_to_ubuntu_VMs.sh -i $IMAGE_FILE -k $KERNEL_VERSION -p $PATCH_FILE
  RV=$?
  # storing kernel version / patch information for next build
  if [ "$RV" -eq 0 ]; then
    mkdir -p $PRE_PATCH_DIR
    echo PRE_KERNEL_VERSION=$KERNEL_VERSION > $PRE_PATCH_DIR/$PRE_PATCH_INFO
    rm -f $PRE_PATCH_FILE
    cp $PATCH_FILE $PRE_PATCH_DIR/.
    echo PRE_PATCH_FILE=$PRE_PATCH_DIR/$(basename $PATCH_FILE) >> $PRE_PATCH_DIR/$PRE_PATCH_INFO
    if [ "$KERNEL_VERSION" != "$PRE_KERNEL_VERSION" ]; then
      rm -rf linux-${PRE_KERNEL_VERSION}
    fi
  fi
  return $RV
}

# Execution

while getopts "hk:p:i:" opt; do
  case "$opt" in
    h) # display usage
      usage
      exit 0
      ;;
    k) # Specify kernel version
      KERNEL_VERSION=$OPTARG
      ;;
    p) # Specify path to a patch file in kvms repository
      PATCH_FILE=$OPTARG
      ;;
    i) # Specify path to Ubuntu VM Image
      IMAGE_FILE=$OPTARG
      ;;
    d) # Specify directory to store kernel patch and version information file
      PRE_PATCH_DIR=$OPTARG
      ;;
    f) # Specify a name for file to store kernel version and patch path
      PRE_PATCH_INFO=$OPTARG
      ;;
   \?) # Invalid option
      usage
      exit 1
      ;;
  esac
done

if [ ! -f "$PRE_PATCH_DIR/$PRE_PATCH_INFO" ]; then
  echo "No previous kernel information found. Patching kernel.."
  update_kernel
  exit $?
fi

. $PRE_PATCH_DIR/$PRE_PATCH_INFO

if [ "$KERNEL_VERSION" != "$PRE_KERNEL_VERSION" ]; then
  echo "New kernel version: $KERNEL_VERSION used. Patching kernel.."
  update_kernel
  exit $?
fi

echo "Comparing kernel patch to previous patch:"
diff $PATCH_FILE $PRE_PATCH_FILE
if [ "$?" -eq 0 ]; then
  echo "Kernel patch has no changes. No need for patching kernel."
  exit 0
elif [ "$?" -eq 1 ]; then
  echo "Kernel patch has been changed. Patching kernel.."
  update_kernel
  exit $?
else
  echo "diff returned $?."
  echo "Kernel patch comparison failed."
  echo "There is probably some environemnt related trouble."
  exit $?
fi
