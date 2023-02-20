# SPDX-License-Identifier: GPL-2.0-only

ifndef BASE_DIR
$(error BASE_DIR is not set. Should point to KVMS base)
endif

HOST_ROOTFS :=  $(BASE_DIR)/images/host/ubuntuhost.qcow2
newname := "$(basename $(HOST_ROOTFS)).plain$(suffix $(HOST_ROOTFS))"
GUEST_IMAGE_DIR := $(BASE_DIR)/guest/images

ROOTFS :=  $(GUEST_IMAGE_DIR)/ubuntuguest.qcow2
ENC_ROOTFS := $(GUEST_IMAGE_DIR)/ubuntu.enc.qcow2

ifeq ($(ENCRYPTED_ROOTFS),1)
DTS_FILE := enc_ubuntu22.dts
QCOW_FILE := $(ENC_ROOTFS)
else
DTS_FILE := ubuntu22.dts
QCOW_FILE := $(ROOTFS)
endif

KEYS_PATH := $(BASE_DIR)/core/keys
IMAGE = $(GUEST_IMAGE_DIR)/Image

GUEST_ID ?= "no"
DTB_ADDR ?= 0x48000000
DTB_FILE ?= $(BASE_DIR)/guest/images/ubuntu22.dtb
GUEST_KEYS_PATH := $(BASE_DIR)/guest/keys
GUEST_SCRIPTS := $(BASE_DIR)/guest/scripts

keys:
	$(MAKE) -C keys all

derivekey: | keys
	$(MAKE) -C src derivekey

initrd: | derivekey
	$(GUEST_SCRIPTS)/create_initfs.sh \
		-r $(GUEST_IMAGE_DIR)/ubuntuguest.qcow2  -o $(GUEST_IMAGE_DIR)/initrd
	$(GUEST_SCRIPTS)/fix_device_tree.sh -i ubuntu22.dts -s `wc -c <  $(GUEST_IMAGE_DIR)/initrd`

$(ENC_ROOTFS) : $(ROOTFS)
	@sudo -E  $(GUEST_SCRIPTS)/encrypt_guest_rootfs.sh -r $(ROOTFS) \
	-o $(ENC_ROOTFS) \
	-k $(shell $(GUEST_SCRIPTS)/derive_key.sh -p $(GUEST_KEYS_PATH)/encryption_priv.pem -s rootfs)

encrypt_rootfs: $(ENC_ROOTFS) | keys

device_tree: | initrd
	dtc -I dts -O dtb -o $(DTB_FILE) $(DTS_FILE)

images: | keys initrd encrypt_rootfs

sign_guest: | device_tree
	$(GUEST_SCRIPTS)/sign_guest_kernel.sh -p $(KEYS_PATH)/signature_priv.pem \
	-k $(IMAGE)  -o $(GUEST_IMAGE_DIR)/$(notdir ${IMAGE}).sign \
	-D "${DTB_FILE}" -d "$(DTB_ADDR)" -i "$(GUEST_ID)" \
	-g $(GUEST_KEYS_PATH)/encryption_pub.txt

.PHONY: encrypt_rootfs keys derivekey device_tree initrd images sign_guest