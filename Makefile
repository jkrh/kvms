export BASE_DIR := $(PWD)
export CORE_DIR := $(BASE_DIR)/core
export OBJDIR := $(BASE_DIR)/.objs
export MBEDDIR := $(BASE_DIR)/mbedtls/library
ifeq ($(KIC_DISABLE),1)
COREDIRS := stdlib core core/crypto core/common platform/common
else
COREDIRS := stdlib ic_loader core core/crypto core/common platform/common
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

BUILD_TOOLS := $(if $(filter virt,$(PLATFORM)),$(TOOLS_QEMU),$(BUILD_TOOLS))
KEYS_PATH := $(CORE_DIR)/keys

$(info KERNEL_DIR:	$(KERNEL_DIR))
$(info PLATFORM:	$(PLATFORM))
$(info CHIPSET:		$(CHIPSET))

all: check prepare librs dirs comp-image
check:
	@[ "${KERNEL_DIR}" ] && echo -n "" || ( echo "KERNEL_DIR is not set"; exit 1 )
	@[ "${PLATFORM}" ] && echo -n "" || ( echo "PLATFORM is not set"; exit 1 )
	@[ "${PLATFORM}" = "virt" ] || [ "${CHIPSET}" ] && echo -n "" || ( echo "CHIPSET is not set"; exit 1 )

prepare:
	@$(HOST_CC) scripts/kallsyms.c -o scripts/kallsyms

librs:
	@./scripts/build-rs.sh

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
	@rm -rf core/librs/target
	@rm -rf core/librs/generated-include/*.h
	@rm -f scripts/kallsyms
	$(MAKE) -Ccore/crypto revert_patch_mbedtls

$(FETCH_SOURCES):
	@echo "Fetching sources.."
	@git submodule update --init

$(BUILD_TOOLS): | $(FETCH_SOURCES)
	@mkdir -p $(TOOLDIR)
	@./scripts/build-tools.sh

tools: $(BUILD_TOOLS)

tools-all: | $(BUILD_TOOLS)
	@mkdir -p $(TOOLDIR)
	@VIRTOOLS=1 ./scripts/build-tools.sh

tools-clean:
	@sudo -E ./scripts/build-tools.sh clean
	@rm -rf $(TOOLDIR)

docs:
	$(MAKE) -C $(TOPDIR)/docs

docs-clean:
	$(MAKE) -C $(TOPDIR)/docs clean

$(OBJDIR): | $(BUILD_TOOLS)
	@mkdir -p $(OBJDIR)/$(PLATFORM)

gdb:
	$(MAKE) CROSS_COMPILE=$(CROSS_COMPILE) KERNEL_DIR=$(KERNEL_DIR) -Cplatform/$(PLATFORM) gdb

run:
	$(MAKE) CROSS_COMPILE=$(CROSS_COMPILE) KERNEL_DIR=$(KERNEL_DIR) -Cplatform/$(PLATFORM) run

poorman:
	$(MAKE) CROSS_COMPILE=$(CROSS_COMPILE) KERNEL_DIR=$(KERNEL_DIR) -Cplatform/$(PLATFORM) poorman

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

hostimage: $(BUILD_TOOLS)
	@sudo -E ./scripts/create_hostimg.sh $(USER)

sign_guest: | gen_key
	$(MAKE) -C guest sign_guest

gen_key:
	$(MAKE) -C $(KEYS_PATH)

guest_images: | gen_key
	make -C guest images

create_vm: | guest_images sign_guest
	@sudo -E ./scripts/create_vm.sh -H $(BASE_DIR)/images/host/ubuntuhost.qcow2 \
	-p home/ubuntu/vm/ubuntu22

comp-image: dirs
	$(MAKE) -C core/imager

comp-image-clean:
	$(MAKE) clean
	$(MAKE) -C core/imager clean

package:
	$(MAKE) -C platform/$(PLATFORM)/tools/sign

coverity:
	./scripts/run-coverity.sh

.PHONY: all check submodule-update tools tools-clean clean gdb qemu package \
	run docs docs-clean coverity prepare \
	gen_key sign_guest ic_loader $(SUBDIRS)
