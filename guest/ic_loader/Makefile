# SPDX-License-Identifier: GPL-2.0-only

PROG := ic_loader
LIBNAME := libic.a

AS_SOURCES := start.S
C_SOURCES := ic_loader.c

override SANITIZER_OPTS := -fno-sanitize=all
override CFLAGS := -FPIC -I$(CORE_DIR) --sysroot=$(TOOLDIR)
override LDFLAGS := -static -T ld.out -L$(BASE_DIR)/.objs
override LDLIBS := -lic -lstdlib

ic_loader.hex:
#
include $(BASE_DIR)/core/common.mk
