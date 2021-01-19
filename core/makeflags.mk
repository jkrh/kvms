# SPDX-License-Identifier: GPL-2.0-only
PVAR := $(shell echo $(PLATFORM) | tr a-z A-Z)
export DEFINES := -D_GNU_SOURCE -D__OPTIMIZE__ -include "config.h"
export WARNINGS := -Wall -pedantic -Wno-pointer-arith -Wno-variadic-macros
export INCLUDES := -I. -I$(KERNEL_DIR) -I$(CORE_DIR) -I$(BASE_DIR)/stdlib \
		-I$(BASE_DIR)/tinycrypt/lib/include/tinycrypt \
		-I$(BASE_DIR)/platform/common \
		-I$(BASE_DIR)/platform/$(PLATFORM)/common \
		-I$(BASE_DIR)/platform/$(PLATFORM) \
		-I$(BASE_DIR)/platform/$(PLATFORM)/$(CHIPSET) \
		-I$(BASE_DIR)/platform/$(PLATFORM)/$(CHIPSET)/$(PRODUCT) \
		-I$(BASE_DIR)/stdlib/sys
export CFLAGS := -march=armv8-a+nofp -fstack-protector-strong -mstrict-align \
		-static -D$(PVAR) -ffreestanding -fno-hosted -std=c99 \
		-mgeneral-regs-only -mno-omit-leaf-frame-pointer \
		-Wstack-protector $(TARGET_CFLAGS) $(DEFINES) $(OPTS) \
		$(INCLUDES) $(WARNINGS)
export ASFLAGS := -D__ASSEMBLY__ $(CFLAGS)
export LDFLAGS := -O1 --gc-sections -L$(BASE_DIR)/tinycrypt/lib \
		-L$(BASE_DIR)/.objs -nostdlib -lstdlib
export SUBMAKEFLAGS := CROSS_COMPILE=$(CROSS_COMPILE) CC=$(CC) LD=$(LD) \
	AR=$(AR) OBJCOPY=$(OBJCOPY) TARGET_CFLAGS=$(TARGET_CFLAGS) \
	KERNEL_DIR=$(KERNEL_DIR)
