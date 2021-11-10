# SPDX-License-Identifier: GPL-2.0-only

#
# Internal
#
PVAR := $(shell echo $(PLATFORM) | tr a-z A-Z)
export DEFINES := -D$(PVAR) -D_GNU_SOURCE -D__OPTIMIZE__ -DMAX_THRESH=1000000 -include "config.h"
export WARNINGS := -Wall -Werror -Wno-pointer-arith -Wno-variadic-macros -Wstack-protector
export INCLUDES := -I. -I$(KERNEL_DIR) -I$(CORE_DIR) -I$(BASE_DIR)/stdlib \
		-I$(BASE_DIR)/mbedtls/include \
		-I$(BASE_DIR)/platform/common \
		-I$(BASE_DIR)/platform/$(PLATFORM)/common \
		-I$(BASE_DIR)/platform/$(PLATFORM) \
		-I$(BASE_DIR)/platform/$(PLATFORM)/$(CHIPSET) \
		-I$(BASE_DIR)/platform/$(PLATFORM)/$(CHIPSET)/$(PRODUCT) \
		-I$(BASE_DIR)/stdlib/sys \
		-I$(OBJDIR)/$(PLATFORM)/$(CHIPSET)/$(PRODUCT)
export CFLAGS := -march=armv8-a+nofp --sysroot=$(TOOLDIR) --no-sysroot-suffix \
		-fstack-protector-strong -mstrict-align -static -ffreestanding \
		-fno-hosted -std=c99 -mgeneral-regs-only -mno-omit-leaf-frame-pointer \
		$(DEFINES) $(OPTS) $(INCLUDES) $(WARNINGS)
export ASFLAGS := -D__ASSEMBLY__ $(CFLAGS)
export LDFLAGS := -O1 -nostdlib \
		-L$(BASE_DIR)/mbedtls/library \
		-L$(BASE_DIR)/.objs
export SUBMAKETOOLS := CROSS_COMPILE=$(CROSS_COMPILE) CC=$(CC) LD=$(LD) \
	AR=$(AR) OBJCOPY=$(OBJCOPY) KERNEL_DIR=$(KERNEL_DIR)
export SUBMAKEFLAGS := $(SUBMAKETOOLS) CFLAGS='$(CFLAGS)'

#
# External
#
export MBEDCONFIG := -DMBEDTLS_USER_CONFIG_FILE=\"$(BASE_DIR)/core/mbedconfig.h\"
export MBEDCFLAGS := '$(MBEDCONFIG) $(CFLAGS) -U_GNU_SOURCE -Wno-implicit-function-declaration'
export MBEDFLAGS := $(SUBMAKETOOLS) CFLAGS=$(MBEDCFLAGS)
