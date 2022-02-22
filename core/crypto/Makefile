# SPDX-License-Identifier: GPL-2.0-only
AS_SOURCES := sha256_armv8.S simd.S

C_SOURCES := sha256_process.c
LIBNAME := libarmv8crypto.a

include $(BASE_DIR)/core/common.mk

all: $(OBJDIR)/$(LIBNAME)
