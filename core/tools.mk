# SPDX-License-Identifier: GPL-2.0-only

export CROSS_COMPILE := aarch64-linux-gnu-
export CC := $(CROSS_COMPILE)gcc
export CXX := $(CROSS_COMPILE)g++
export LD := $(CROSS_COMPILE)ld
export AS := $(CROSS_COMPILE)as
export AR := $(CROSS_COMPILE)ar
export AS := $(CROSS_COMPILE)gcc
export OBJCOPY := $(CROSS_COMPILE)objcopy
export RANLIB := $(CROSS_COMPILE)ranlib
export TOOLDIR := $(BASE_DIR)/buildtools
export PATH=$(TOOLDIR)/bin:$(TOOLDIR)/usr/bin:/bin:/usr/bin:/usr/local/bin
export TOOLS_GCC := $(TOOLDIR)/usr/bin/$(CC)
export FETCH_SOURCES := oss/gcc/configure
export SED := sed
