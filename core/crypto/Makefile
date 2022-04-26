# SPDX-License-Identifier: GPL-2.0-only
HOST_COMMON_PATCH_DIR = $(BASE_DIR)/patches/host/common
MBEDTLS_AES_PATCH_FILE = $(HOST_COMMON_PATCH_DIR)/0001-mbedtls-armv8ce-support-added.patch
MBEDTLS_AES_PATCHED = $(shell git -C $(BASE_DIR)/mbedtls apply --check $(MBEDTLS_AES_PATCH_FILE) 2>&1 | wc -l)

AS_SOURCES := sha256_armv8.S simd.S

C_SOURCES := sha256_process.c
LIBNAME := libarmv8crypto.a

include $(BASE_DIR)/core/common.mk

all: $(OBJDIR)/$(LIBNAME)

patch_mbedtls:
ifeq ($(MBEDTLS_AES_PATCHED), 0)
	@echo "Patching mbedtls for armv8ce support"
	git -C $(BASE_DIR)/mbedtls apply $(MBEDTLS_AES_PATCH_FILE)
endif

revert_patch_mbedtls:
ifneq ($(MBEDTLS_AES_PATCHED), 0)
	@echo "Removing armv8ce patch from mbedtls"
	git -C $(BASE_DIR)/mbedtls apply -R $(MBEDTLS_AES_PATCH_FILE)
endif

.PHONY: patch_mbedtls revert_patch_mbedtls
