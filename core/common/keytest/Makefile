# SPDX-License-Identifier: GPL-2.0-only
CROSS_COMPILE := aarch64-linux-gnu-
CC := $(CROSS_COMPILE)gcc
BASE_DIR := $(TOPDIR)
TOOLDIR := $(BASE_DIR)/buildtools
PATH=$(TOOLDIR)/bin:$(TOOLDIR)/usr/bin:/bin:/usr/bin:/usr/local/bin
PVAR := $(shell echo $(PLATFORM) | tr a-z A-Z)

INCLUDES += -I$(BASE_DIR)/mbedtls/include -I.. -I$(BASE_DIR)/core  -I.. -I$(BASE_DIR)/core/common
INCLUDES += -I$(BASE_DIR)/platform/common -I$(BASE_DIR)/platform/virt -I$(BASE_DIR)/oss/linux -I$(BASE_DIR)/stdlib

CFLAGS := -march=armv8-a+nofp --sysroot=$(TOOLDIR) --no-sysroot-suffix $(INCLUDES) $(DEFINES) -fno-sanitize=all
CFLAGS +=  -lmbedtls -lmbedcrypto -larmv8crypto
CFLAGS += -L$(BASE_DIR)/mbedtls/library -L$(BASE_DIR)/.objs --static
keytest: keytest.c utils.c ../keystore.c
	$(CC) keytest.c ../keystore.c utils.c $(CFLAGS) -o keytest

clean:
	rm -f keystore.o keytest.o keytest

