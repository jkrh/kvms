# SPDX-License-Identifier: GPL-2.0-only

export HOST_CC := gcc
export CROSS_COMPILE := aarch64-linux-gnu-
export CC := $(CROSS_COMPILE)gcc
export CXX := $(CROSS_COMPILE)g++
export LD := $(CROSS_COMPILE)ld
export AS := $(CROSS_COMPILE)as
export AR := $(CROSS_COMPILE)ar
export AS := $(CROSS_COMPILE)gcc
export NM := $(CROSS_COMPILE)nm
export OBJCOPY := $(CROSS_COMPILE)objcopy
export RANLIB := $(CROSS_COMPILE)ranlib
export TOOLDIR := $(BASE_DIR)/buildtools
export PATH=$(TOOLDIR)/bin:$(TOOLDIR)/usr/bin:/bin:/usr/bin:/usr/local/bin
export LD_LIBRARY_PATH=$(TOOLDIR)/lib:$(TOOLDIR)/usr/lib
export LD_RUN_PATH=$(TOOLDIR)/lib:$(TOOLDIR)/usr/lib
export TOOLS_QEMU := $(TOOLDIR)/usr/bin/qemu-system-aarch64
export FETCH_SOURCES := oss/gcc/configure
export SED := sed
export DOXYGEN := doxygen
export BUILD_TOOLS := $(TOOLDIR)/usr/bin/aarch64-linux-gnu-gcc
