# SPDX-License-Identifier: GPL-2.0-only

#
# Internal
#
PVAR := $(shell echo $(PLATFORM) | tr a-z A-Z)
HOSTNAME := $(shell uname -n)
GHEAD := $(shell git rev-parse HEAD)

export DEFINES := -D$(PVAR) -D_GNU_SOURCE -D__OPTIMIZE__ -DBUILDHOST=$(HOSTNAME) \
		-DBUILDUSER=$(USER) -DGHEAD=$(GHEAD) -DMAX_THRESH=$(MAX_PAGING_BLOCKS) \
		-DMAX_PAGING_BLOCKS=$(MAX_PAGING_BLOCKS) -DUNSAFE_LZ4 \
		-DMBEDTLS_USER_CONFIG_FILE=\"$(BASE_DIR)/core/mbedconfig.h\" -include "config.h"
export WARNINGS := -Wall -Werror -Wno-pointer-arith -Wno-variadic-macros \
		-Wstack-protector -Wstack-usage=8192 -Wno-implicit-function-declaration
export INCLUDES := -I. \
		-I$(KERNEL_DIR) \
		-I$(CORE_DIR) \
		-I$(CORE_DIR)/common \
		-I$(BASE_DIR)/stdlib \
		-I$(BASE_DIR)/mbedtls/include \
		-I$(BASE_DIR)/platform/common \
		-I$(BASE_DIR)/platform/$(PLATFORM)/common \
		-I$(BASE_DIR)/platform/$(PLATFORM) \
		-I$(BASE_DIR)/platform/$(PLATFORM)/$(CHIPSET) \
		-I$(BASE_DIR)/platform/$(PLATFORM)/$(CHIPSET)/$(PRODUCT) \
		-I$(BASE_DIR)/stdlib/sys \
		-I$(OBJDIR)/$(PLATFORM)/$(CHIPSET)/$(PRODUCT) \
		-I$(CORE_DIR)/librs/include \
		-I$(CORE_DIR)/keys
#
# Due to size constraints on some platforms
#
ifeq ($(PLATFORM), virt)
export SANITIZER_OPTS ?= -fsanitize=return -fsanitize=signed-integer-overflow \
		-fsanitize=vla-bound -fsanitize=null -fsanitize=object-size \
		-fsanitize=bounds -fsanitize-address-use-after-scope
else
export SANITIZER_OPTS ?=
endif

ifeq ($(PTRAUTH),1)
export ARM_BASE=armv8.3-a
else
export ARM_BASE=armv8-a
endif

ifeq ($(MEMTAG),1)
export ARM_BASE=armv8.5-a
endif

export CFLAGS := \
	--sysroot=$(TOOLDIR) --no-sysroot-suffix -fstack-protector-strong -mstrict-align \
	-static -ffreestanding -fno-hosted -std=c99 -fno-omit-frame-pointer -fno-data-sections \
	$(DEFINES) $(OPTS) $(INCLUDES) $(WARNINGS) $(SANITIZER_OPTS)

ifeq ($(USE_HW_CRYPTO),1)
export CFLAGS += -DUSE_HW_CRYPTO=1
export CFLAGS_MBED := $(CFLAGS) -march=$(ARM_BASE)+crypto
else
export CFLAGS_MBED += $(CFLAGS) -march=$(ARM_BASE)+nosimd -mgeneral-regs-only
endif
export CFLAGS += -march=$(ARM_BASE)+nosimd -mgeneral-regs-only

ifeq ($(PTRAUTH),1)
export CFLAGS += -DPTRAUTH
endif

ifeq ($(MEMTAG),1)
export CFLAGS += -march=$(ARM_BASE)+memtag
endif

ifneq (,$(filter 1,$(PTRAUTH) $(MEMTAG)))
export CFLAGS += -mbranch-protection=standard
endif

export ASFLAGS := -D__ASSEMBLY__ $(CFLAGS)
export AFLAGS := -D__ASSEMBLY__ \
		-I$(KERNEL_DIR)/usr/include
export LDFLAGS := -nostdlib -O1 --gc-sections --build-id=none \
		-L$(BASE_DIR)/mbedtls/library \
		-L$(BASE_DIR)/.objs

#
# External
#
export SUBMAKETOOLS := CROSS_COMPILE=$(CROSS_COMPILE) CC=$(CC) LD=$(LD) \
	AR=$(AR) OBJCOPY=$(OBJCOPY) KERNEL_DIR=$(KERNEL_DIR)
export SUBMAKEFLAGS := $(SUBMAKETOOLS) CFLAGS='$(CFLAGS)'
export MBEDFLAGS := $(SUBMAKETOOLS) CFLAGS='$(CFLAGS_MBED) -U_GNU_SOURCE'
