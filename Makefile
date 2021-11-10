export BASE_DIR := $(PWD)
export CORE_DIR := $(BASE_DIR)/core
export OBJDIR := $(BASE_DIR)/.objs

ifeq ($(PLATFORM),virt)
SUBDIRS := stdlib core platform/$(PLATFORM)
KERNEL_DIR := $(BASE_DIR)/oss/linux
else
SUBDIRS := platform/$(PLATFORM) stdlib core platform/$(PLATFORM)/common
endif
include core/tools.mk
include core/makevars.mk
include core/makeflags.mk

$(info KERNEL_DIR:	$(KERNEL_DIR))
$(info PLATFORM:	$(PLATFORM))
$(info CHIPSET:		$(CHIPSET))

#
# Android QEMU defaults. The host QEMU is always built with these enabled.
#
export OPENGL := 1
export SPICE := 1
export VIRGL := 1
export SDL := 1

all: check dirs
check:
	@[ "${KERNEL_DIR}" ] && echo -n "" || ( echo "KERNEL_DIR is not set"; exit 1 )
	@[ "${PLATFORM}" ] && echo -n "" || ( echo "PLATFORM is not set"; exit 1 )
	@[ "${PLATFORM}" = "virt" ] || [ "${CHIPSET}" ] && echo -n "" || ( echo "CHIPSET is not set"; exit 1 )

dirs: $(SUBDIRS) | $(OBJDIR)
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

$(FETCH_SOURCES):
	@echo "Fetching sources.."
	@git submodule update --init

$(TOOLS_GCC): | $(FETCH_SOURCES)
	@mkdir -p $(TOOLDIR)
	./scripts/build-tools.sh

tools: $(TOOLS_GCC)

tools-clean:
	./scripts/build-tools.sh clean
	@rm -rf $(TOOLDIR)

$(OBJDIR): | $(TOOLS_GCC)
	@mkdir -p $(OBJDIR)/$(PLATFORM)

gdb:
	$(MAKE) CROSS_COMPILE=$(CROSS_COMPILE) KERNEL_DIR=$(KERNEL_DIR) -Cplatform/$(PLATFORM) gdb

run:
	$(MAKE) CROSS_COMPILE=$(CROSS_COMPILE) KERNEL_DIR=$(KERNEL_DIR) -Cplatform/$(PLATFORM) run

test: | module-test

module-test:
	python scripts/module-test.py $(MODULE)

android-qemu:
	./scripts/build-android-qemu.sh

package:
	$(MAKE) -C platform/$(PLATFORM)/tools/sign

.PHONY: all check submodule-update tools tools-clean clean gdb qemu package run $(SUBDIRS)
