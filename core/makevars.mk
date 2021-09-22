# SPDX-License-Identifier: GPL-2.0-only
#
# Build controls. Note that currently only builds that have
# DEBUG set to 1 will produce console output. Production
# builds will default to ram log readable via the hypervisor
# driver.
#
ifeq ($(DEBUG),1)
BUILDOPTS := -g -Os -DDEBUG -DCRASHDUMP
else
BUILDOPTS := -g -O2 -D_FORTIFY_SOURCE -DCRASHDUMP
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
