# SPDX-License-Identifier: GPL-2.0-only
#
# Build controls. Note that currently only builds that have
# DEBUG set to 1 will produce console output. Production
# builds will default to ram log readable via the hypervisor
# driver.
#
ifdef DEBUG
BUILDOPTS := -g -Os -DCRASHDUMP
else
BUILDOPTS := -g -O2 -D_FORTIFY_SOURCE -DCRASHDUMP
endif
# Debug levels
ifeq ($(DEBUG),1)
BUILDOPTS += -DDEBUG
endif
ifeq ($(DEBUG),2)
BUILDOPTS += -DDEBUG=2
endif
#
# Default build will include headers from linux kernel and
# work as KVM extension. Standalone build on the other hand
# will compile without the defines from linux kernel headers.
# Standalone version is intended to work as basis for things
# like host memory protection and intrusion detection.
#
ifeq ($(STANDALONE),1)
BUILDOPTS += -DSTANDALONE
endif
#
export OPTS := $(BUILDOPTS)
#
# Use to make qemu wait for debugger connection, aka
# 'make gdb'
#
ifeq ($(DEBUGGER),1)
export DEBUGOPTS := -S -s
endif
#
# Use to invoke QEMU under a host gdb session. It
# will invoke qemu with full debug symbols.
#
ifeq ($(QEMUDEBUG),1)
endif

#
# Use to turn on the graphics for the virt host emulation
#
ifeq ($(GRAPHICS),1)
export GRAPHICS=1
endif
