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
CERT_REQ_FILE ?= $(GUEST_IMAGE_DIR)/cert_req.crt
CERT_FILE ?= $(GUEST_IMAGE_DIR)/cert.crt

GUEST_ID ?= "no"
DTB_ADDR ?= 0x48000000
DTB_FILE ?= $(GUEST_IMAGE_DIR)/ubuntu22.dtb
INITRD_ADDR ?= 0x48008000
INITRD_FILE ?= $(GUEST_IMAGE_DIR)/initrd

GUEST_KEYS_PATH := $(BASE_DIR)/guest/keys
GUEST_SCRIPTS := $(BASE_DIR)/guest/scripts

keys:
	$(MAKE) -C keys all

derivekey: | keys
	$(MAKE) -C src derivekey

initrd: | derivekey
	$(GUEST_SCRIPTS)/create_initfs.sh \
		-r $(GUEST_IMAGE_DIR)/ubuntuguest.qcow2  -o $(INITRD_FILE)
	$(GUEST_SCRIPTS)/fix_device_tree.sh \
		-i ubuntu22.dts \
		-o enc_ubuntu22.dts \
		-s `wc -c <  $(GUEST_IMAGE_DIR)/initrd`

$(ENC_ROOTFS) : $(ROOTFS)
	@sudo -E  $(GUEST_SCRIPTS)/encrypt_guest_rootfs.sh -r $(ROOTFS) \
		-o $(ENC_ROOTFS) \
		-k $(shell $(GUEST_SCRIPTS)/derive_key.sh \
			-p $(GUEST_KEYS_PATH)/encryption_priv.pem \
			-s rootfs)

encrypt_rootfs: $(ENC_ROOTFS) | keys

device_tree: | initrd
	dtc -I dts -O dtb -o $(DTB_FILE) $(DTS_FILE)

$(CERT_FILE): | keys
	$(GUEST_SCRIPTS)/create_cert_req.sh  \
		-s $(GUEST_KEYS_PATH)/sign_pub.txt \
		-e $(GUEST_KEYS_PATH)/encryption_pub.txt \
		-o $(CERT_REQ_FILE)
	# send certificate creation request
	$(BASE_DIR)/scripts/sign_guest_cert.sh \
		-i $(CERT_REQ_FILE) -o $(CERT_FILE)

images: | keys initrd encrypt_rootfs

sign_guest: $(CERT_FILE) | device_tree
	$(GUEST_SCRIPTS)/sign_guest_kernel.sh \
		-p $(GUEST_KEYS_PATH)/sign_priv.pem \
		-k "$(IMAGE)" \
		-o "$(GUEST_IMAGE_DIR)"/$(notdir ${IMAGE}).sign \
		-D "${DTB_FILE}" -d "$(DTB_ADDR)" \
		-I "${INITRD_FILE}" -i "$(INITRD_ADDR)" \
		-g "$(GUEST_ID)" \
		-c "$(CERT_FILE)"
.PHONY: encrypt_rootfs keys derivekey device_tree initrd images sign_guest
