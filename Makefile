export BASE_DIR := $(PWD)
export CORE_DIR := $(BASE_DIR)/core
export OBJDIR := $(BASE_DIR)/.objs

ifeq ($(PLATFORM),virt)
SUBDIRS := stdlib core core/crypto core/common platform/common platform/$(PLATFORM)
else
SUBDIRS := platform/$(PLATFORM) stdlib core core/crypto core/common platform/common platform/$(PLATFORM)/common
endif
include core/tools.mk
include core/makevars.mk
include core/makeflags.mk
KEYS_PATH := $(BASE_DIR)/guest/keys
ID_LOADER_PATH := $(BASE_DIR)/guest/ic_loader
GUEST_ID := ""

$(info KERNEL_DIR:	$(KERNEL_DIR))
$(info PLATFORM:	$(PLATFORM))
$(info CHIPSET:		$(CHIPSET))

all: check dirs
check:
	@[ "${KERNEL_DIR}" ] && echo -n "" || ( echo "KERNEL_DIR is not set"; exit 1 )
	@[ "${PLATFORM}" ] && echo -n "" || ( echo "PLATFORM is not set"; exit 1 )
	@[ "${PLATFORM}" = "virt" ] || [ "${CHIPSET}" ] && echo -n "" || ( echo "CHIPSET is not set"; exit 1 )

dirs: $(SUBDIRS) | $(OBJDIR) gen_key
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
	$(MAKE) -Ccore/crypto revert_patch_mbedtls

$(FETCH_SOURCES):
	@echo "Fetching sources.."
	@git submodule update --init

$(TOOLS_QEMU): | $(FETCH_SOURCES)
	@mkdir -p $(TOOLDIR)
	./scripts/build-tools.sh

tools: $(TOOLS_QEMU)

tools-clean:
	./scripts/build-tools.sh clean
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
	./scripts/build-target-qemu.sh

sign_guest: gen_key ic_loader
	@[ "${IMAGE}" ] && echo -n "" || ( echo "IMAGE is not set"; exit 1 )
	$(BASE_DIR)/scripts/sign_guest_kernel.sh -p $(KEYS_PATH)/guest_image_priv.pem \
	-k $(IMAGE) -l $(ID_LOADER_PATH)/ic_loader -o $(IMAGE).sign -i $(GUEST_ID)

gen_key:
	$(MAKE) -C $(KEYS_PATH)

ic_loader:
	$(MAKE) -C $(ID_LOADER_PATH) ic_loader

package:
	$(MAKE) -C platform/$(PLATFORM)/tools/sign

coverity:
	./scripts/run-coverity.sh

.PHONY: all check submodule-update tools tools-clean clean gdb qemu package run docs docs-clean coverity \
 		gen_key sign_guest ic_loader $(SUBDIRS)
