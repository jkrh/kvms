# SPDX-License-Identifier: GPL-2.0-only

#
# Internal
#
PVAR := $(shell echo $(PLATFORM) | tr a-z A-Z)
export DEFINES := -D$(PVAR) -D_GNU_SOURCE -D__OPTIMIZE__ \
		-DMAX_THRESH=$(MAX_PAGING_BLOCKS) -DMAX_PAGING_BLOCKS=$(MAX_PAGING_BLOCKS) \
		-DMBEDTLS_USER_CONFIG_FILE=\"$(BASE_DIR)/core/mbedconfig.h\" -include "config.h"
export WARNINGS := -Wall -Werror -Wno-pointer-arith -Wno-variadic-macros \
		-Wstack-protector -Wstack-usage=8192 -Wno-implicit-function-declaration
export INCLUDES := -I. -I$(KERNEL_DIR) -I$(CORE_DIR) -I$(CORE_DIR)/common -I$(BASE_DIR)/stdlib \
		-I$(BASE_DIR)/mbedtls/include \
		-I$(BASE_DIR)/platform/common \
		-I$(BASE_DIR)/platform/$(PLATFORM)/common \
		-I$(BASE_DIR)/platform/$(PLATFORM) \
		-I$(BASE_DIR)/platform/$(PLATFORM)/$(CHIPSET) \
		-I$(BASE_DIR)/platform/$(PLATFORM)/$(CHIPSET)/$(PRODUCT) \
		-I$(BASE_DIR)/stdlib/sys \
		-I$(OBJDIR)/$(PLATFORM)/$(CHIPSET)/$(PRODUCT)

#
# Due to size constraints on some platforms
#
ifeq ($(PLATFORM), virt)
export SANITIZER_OPTS := -fsanitize=return -fsanitize=signed-integer-overflow \
		-fsanitize=vla-bound -fsanitize=null -fsanitize=object-size \
		-fsanitize=bounds -fsanitize-address-use-after-scope
else
export SANITIZER_OPTS :=
endif

ifeq ($(USE_HW_CRYPTO),1)
export CFLAGS := -march=armv8-a+crypto -DUSE_HW_CRYPTO=1
else
export CFLAGS := -march=armv8-a+nosimd -mgeneral-regs-only
endif

export CFLAGS += \
	--sysroot=$(TOOLDIR) --no-sysroot-suffix -fstack-protector-strong -mstrict-align \
	-static -ffreestanding -fno-hosted -std=c99 -fno-omit-frame-pointer -fno-data-sections \
	$(DEFINES) $(OPTS) $(INCLUDES) $(WARNINGS) $(SANITIZER_OPTS)

export ASFLAGS := -D__ASSEMBLY__ $(CFLAGS)
export LDFLAGS := -nostdlib -O1 --gc-sections --build-id=none \
		-L$(BASE_DIR)/mbedtls/library \
		-L$(BASE_DIR)/.objs

#
# External
#
export SUBMAKETOOLS := CROSS_COMPILE=$(CROSS_COMPILE) CC=$(CC) LD=$(LD) \
	AR=$(AR) OBJCOPY=$(OBJCOPY) KERNEL_DIR=$(KERNEL_DIR)
export SUBMAKEFLAGS := $(SUBMAKETOOLS) CFLAGS='$(CFLAGS)'
export MBEDFLAGS := $(SUBMAKETOOLS) CFLAGS='$(CFLAGS) -U_GNU_SOURCE'
