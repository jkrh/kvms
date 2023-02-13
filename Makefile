export BASE_DIR := $(PWD)
export CORE_DIR := $(BASE_DIR)/core
export OBJDIR := $(BASE_DIR)/.objs
ifeq ($(KIC_DISABLE),1)
COREDIRS := stdlib core core/crypto core/common platform/common
else
COREDIRS := stdlib guest/ic_loader core core/crypto core/common platform/common
endif

ifeq ($(PLATFORM),virt)
SUBDIRS := $(COREDIRS) platform/$(PLATFORM)
else
SUBDIRS := platform/$(PLATFORM) $(COREDIRS) platform/$(PLATFORM)/common
endif
include core/tools.mk
-include platform/$(PLATFORM)/makevars.mk
include core/makevars.mk
include core/makeflags.mk

KEYS_PATH := $(BASE_DIR)/guest/keys
GUEST_ID := ""
IMAGE ?= images/guest/Image
DTB_ADDR ?= 0x48000000
DTB_FILE ?= $(BASE_DIR)/.objs/ubuntu22.dtb

$(info KERNEL_DIR:	$(KERNEL_DIR))
$(info PLATFORM:	$(PLATFORM))
$(info CHIPSET:		$(CHIPSET))

all: check dirs comp-image
check:
	@[ "${KERNEL_DIR}" ] && echo -n "" || ( echo "KERNEL_DIR is not set"; exit 1 )
	@[ "${PLATFORM}" ] && echo -n "" || ( echo "PLATFORM is not set"; exit 1 )
	@[ "${PLATFORM}" = "virt" ] || [ "${CHIPSET}" ] && echo -n "" || ( echo "CHIPSET is not set"; exit 1 )

dirs: gen_key $(SUBDIRS) | $(OBJDIR)
	@./scripts/gen-symhdr.sh
	$(MAKE) -Ccore/crypto patch_mbedtls
	$(MAKE) $(MBEDFLAGS) -Cmbedtls/library static
	@for DIR in $(SUBDIRS); do \
		$(MAKE) $(SUBMAKEFLAGS) -C$${DIR}; \
	done

clean:
	$(MAKE) $(MBEDFLAGS) -Cmbedtls/library clean
	@for DIR in $(SUBDIRS); do \
		$(MAKE) $(SUBMAKEFLAGS) -C$${DIR} clean; \
	done
	@rm -rf $(OBJDIR)
	@rm -rf core/generated
	$(MAKE) -Ccore/crypto revert_patch_mbedtls

$(FETCH_SOURCES):
	@echo "Fetching sources.."
	@git submodule update --init

$(TOOLS_QEMU): | $(FETCH_SOURCES)
	@mkdir -p $(TOOLDIR)
	@./scripts/build-tools.sh

tools: $(TOOLS_QEMU)

tools-clean:
	@./scripts/build-tools.sh clean
	@rm -rf $(TOOLDIR)

docs:
	$(MAKE) -C $(TOPDIR)/docs

docs-clean:
	$(MAKE) -C $(TOPDIR)/docs clean

$(OBJDIR): | $(TOOLS_QEMU)
	@mkdir -p $(OBJDIR)/$(PLATFORM)

gdb:
	$(MAKE) CROSS_COMPILE=$(CROSS_COMPILE) KERNEL_DIR=$(KERNEL_DIR) -Cplatform/$(PLATFORM) gdb

run:
	$(MAKE) CROSS_COMPILE=$(CROSS_COMPILE) KERNEL_DIR=$(KERNEL_DIR) -Cplatform/$(PLATFORM) run

test: | module-test

module-test:
	python scripts/module-test.py $(MODULE)

target-qemu:
	@./scripts/build-target-qemu.sh

target-qemu-clean:
	@./scripts/build-target-qemu.sh clean

target-qemu-distclean:
	@./scripts/build-target-qemu.sh distclean

guestimage:
	@sudo -E ./scripts/create_guestimg.sh $(USER)

hostimage: $(TOOLS_QEMU)
	@sudo -E ./scripts/create_hostimg.sh $(USER)

sign_guest: gen_key
	dtc -I dts -O dtb -o $(BASE_DIR)/.objs/ubuntu22.dtb platform/virt/ubuntu22.dts
	$(BASE_DIR)/scripts/sign_guest_kernel.sh -p $(KEYS_PATH)/guest_image_priv.pem \
	-k $(IMAGE) -d "${DTB_ADDR}" -o .objs/$(notdir ${IMAGE}).sign \
	-D "${DTB_FILE}" -i "$(GUEST_ID)"

gen_key:
	$(MAKE) -C $(KEYS_PATH)

create_vm:
	@sudo -E ./scripts/create_vm.sh -H $(BASE_DIR)/images/host/ubuntuhost.qcow2 \
	-p home/ubuntu/vm/ubuntu22 -g  $(BASE_DIR)/images/guest/ubuntuguest.qcow2

comp-image: dirs
	$(MAKE) -C core/imager

comp-image-clean:
	$(MAKE) clean
	$(MAKE) -C core/imager clean

package:
	$(MAKE) -C platform/$(PLATFORM)/tools/sign

coverity:
	./scripts/run-coverity.sh

.PHONY: all check submodule-update tools tools-clean clean gdb qemu package run docs docs-clean coverity \
		gen_key sign_guest ic_loader $(SUBDIRS)
