# SPDX-License-Identifier: GPL-2.0-only
AS_SOURCES := ventry.S kentry.S spinlock.S cache.S \
	mhelpers.S
C_SOURCES := armtrans.c main.c hvccall.c \
	smccall.c guest.c psci.c mm.c \
	mtree.c heap.c hyplogs.c kjump.c \
	validate.c tables.c
LIBNAME := libcore.a

include $(BASE_DIR)/core/common.mk

all: $(OBJDIR)/$(LIBNAME)
