# SPDX-License-Identifier: GPL-2.0-only
AS_SOURCES := ventry.S kentry.S cache.S \
	mhelpers.S guest_entry.S
C_SOURCES := armtrans.c main.c hvccall.c \
	smccall.c guest.c psci.c mm.c \
	mtree.c kjump.c host.c \
	tables.c gic.c patrack.c \
	oplocks.c rwlock.c kic.c shared_secret.c

ifdef DEBUG
C_SOURCES += kallsyms.c stacktrace.c
endif

ifdef TESTS
C_SOURCES += validate.c
endif

LIBNAME := libcore.a

include $(BASE_DIR)/core/common.mk

all: $(OBJDIR)/$(LIBNAME)
