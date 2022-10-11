
C_SOURCES := heap.c  keystore.c hyplogs.c ecdsa.c
LIBNAME := libcommon.a

include $(BASE_DIR)/core/common.mk

all: $(OBJDIR)/$(LIBNAME)

.PHONY: patch_mbedtls revert_patch_mbedtls
