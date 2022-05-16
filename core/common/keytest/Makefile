# SPDX-License-Identifier: GPL-2.0-only
CROSS_COMPILE := aarch64-linux-gnu-
CC := $(CROSS_COMPILE)gcc
BASE_DIR := $(TOPDIR)
TOOLDIR := $(BASE_DIR)/buildtools
PATH=$(TOOLDIR)/bin:$(TOOLDIR)/usr/bin:/bin:/usr/bin:/usr/local/bin
PVAR := $(shell echo $(PLATFORM) | tr a-z A-Z)
export DEFINES := -D$(PVAR) -D_GNU_SOURCE -D__OPTIMIZE__ -DMAX_THRESH=1000000 -include "config.h"

INCLUDES += -I$(BASE_DIR)/mbedtls/include -I.. -I$(BASE_DIR)/core  -I.. -I$(BASE_DIR)/core/common
INCLUDES += -I$(BASE_DIR)/platform/common -I$(BASE_DIR)/platform/virt -I$(BASE_DIR)/oss/linux -I$(BASE_DIR)/stdlib

CFLAGS := -march=armv8-a+nofp --sysroot=$(TOOLDIR) --no-sysroot-suffix $(INCLUDES) $(DEFINES)
CFLAGS += -lcommon -lmbedtls -lmbedcrypto -larmv8crypto -lcommon
CFLAGS += -L$(BASE_DIR)/mbedtls/library -L$(BASE_DIR)/.objs --static

keytest: keytest.c
	$(CC) keytest.c $(CFLAGS) -o keytest

clean:
	rm -f keystore.o keytest.o keytest

