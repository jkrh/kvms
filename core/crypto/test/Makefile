# SPDX-License-Identifier: GPL-2.0-only
CROSS_COMPILE := aarch64-linux-gnu-
CC := $(CROSS_COMPILE)gcc
BASE_DIR := ../../..
TOOLDIR := $(BASE_DIR)/buildtools
PATH=$(TOOLDIR)/bin:$(TOOLDIR)/usr/bin:/bin:/usr/bin:/usr/local/bin

INCLUDES += -I$(BASE_DIR)/mbedtls/include -I.. -I$(BASE_DIR)/core

CFLAGS := -march=armv8-a+nofp --sysroot=$(TOOLDIR) --no-sysroot-suffix $(INCLUDES)
CFLAGS += -lmbedtls -lmbedcrypto -L$(BASE_DIR)/mbedtls/library --static
#CFLAGS += -DTESTS_BUILD

sha256test: sha256test.c
	 $(CC) sha256test.c $(CFLAGS) ../sha256_process.c ../sha256_armv8.S -o sha256test

clean:
	rm -f sha256test sha256test.o ../sha256_armv8.o ../sha256_process.o
