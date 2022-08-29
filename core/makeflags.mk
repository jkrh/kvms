# SPDX-License-Identifier: GPL-2.0-only

#
# Internal
#
PVAR := $(shell echo $(PLATFORM) | tr a-z A-Z)
export DEFINES := -D$(PVAR) -D_GNU_SOURCE -D__OPTIMIZE__ -DMAX_THRESH=1000000 -include "config.h"
export WARNINGS := -Wall -Werror -Wno-pointer-arith -Wno-variadic-macros -Wstack-protector
export INCLUDES := -I. -I$(KERNEL_DIR) -I$(CORE_DIR) -I$(CORE_DIR)/common -I$(BASE_DIR)/stdlib \
		-I$(BASE_DIR)/mbedtls/include \
		-I$(BASE_DIR)/platform/common \
		-I$(BASE_DIR)/platform/$(PLATFORM)/common \
		-I$(BASE_DIR)/platform/$(PLATFORM) \
		-I$(BASE_DIR)/platform/$(PLATFORM)/$(CHIPSET) \
		-I$(BASE_DIR)/platform/$(PLATFORM)/$(CHIPSET)/$(PRODUCT) \
		-I$(BASE_DIR)/stdlib/sys \
		-I$(OBJDIR)/$(PLATFORM)/$(CHIPSET)/$(PRODUCT)

ARMV8_NOSIMD := -march=armv8-a+nosimd -mgeneral-regs-only
ARMV8_SIMD := -march=armv8-a+crypto -DUSE_HW_CRYPTO=1

CFLAGS_COMMON := --sysroot=$(TOOLDIR) --no-sysroot-suffix \
		-fstack-protector-strong -mstrict-align -static -ffreestanding \
		-fno-hosted -std=c99  -mno-omit-leaf-frame-pointer -fno-data-sections \
		$(DEFINES) $(OPTS) $(INCLUDES) $(WARNINGS)

export CFLAGS := $(ARMV8_NOSIMD) $(CFLAGS_COMMON)
export CFLAGS_SIMD := $(ARMV8_SIMD) $(CFLAGS_COMMON)
export ASFLAGS := -D__ASSEMBLY__ $(CFLAGS)
export LDFLAGS := -nostdlib -O1 \
		--gc-sections --build-id=none \
		-L$(BASE_DIR)/mbedtls/library \
		-L$(BASE_DIR)/.objs
export SUBMAKETOOLS := CROSS_COMPILE=$(CROSS_COMPILE) CC=$(CC) LD=$(LD) \
	AR=$(AR) OBJCOPY=$(OBJCOPY) KERNEL_DIR=$(KERNEL_DIR)
export SUBMAKEFLAGS := $(SUBMAKETOOLS) CFLAGS='$(CFLAGS)'

#
# External
#
export MBEDCONFIG := -DMBEDTLS_USER_CONFIG_FILE=\"$(BASE_DIR)/core/mbedconfig.h\"
ifeq ($(USE_HW_CRYPTO),1)
# If platform uses armv8 crypto extention then CLAGS must not contain -mgeneral-regs-only flag
# and it should contain -march=armv8-a+crypto
export MBEDCFLAGS := '$(MBEDCONFIG) $(CFLAGS_SIMD) -U_GNU_SOURCE -Wno-implicit-function-declaration -include "config.h"'
else
export MBEDCFLAGS := '$(MBEDCONFIG) $(CFLAGS) -U_GNU_SOURCE -Wno-implicit-function-declaration -include "config.h"'
endif
export MBEDFLAGS := $(SUBMAKETOOLS) CFLAGS=$(MBEDCFLAGS)
