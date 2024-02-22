# SPDX-License-Identifier: GPL-2.0-only
#
# Build controls. Note that currently only builds that have
# DEBUG set to 1 will produce console output. Production
# builds will default to ram log readable via the hypervisor
# driver.
#
ifdef DEBUG
BUILDOPTS := -g3 -Os -DCRASHDUMP
# Let's enable kallsyms in debug mode only.
# TODO: add KALLSYMS_BASE_RELATIVE and KALLSYMS_ABSOLUTE_PERCPU
BUILDOPTS += -DKALLSYMS -DKALLSYMS_ALL
BUILDOPTS += -DSTACKTRACE
else
BUILDOPTS := -g1 -Os -D_FORTIFY_SOURCE=1 -Wl,-O2
endif

#
# Debug levels. Setting of 1 will give you the output on
# console; setting of 2 will disable the driver lock flags.
#
ifeq ($(DEBUG),1)
BUILDOPTS += -DDEBUG=1
endif
ifeq ($(DEBUG),2)
BUILDOPTS += -DDEBUG=2
endif

#
# Define the paging data stash size for each VM. This is the amount
# of pages (small or large) each VM can store in the page integrity
# stash.
#
ifndef MAX_PAGING_BLOCKS
MAX_PAGING_BLOCKS := 64000
endif

#
# Use pre-shared virtio memory. Requires guest support.
#
ifeq ($(USE_EXT_SHARES),1)
BUILDOPTS += -DUSE_EXT_SHARES
endif

#
# Define if hardware cryptographic extensions should be used for
# the aes / sha computations.
#
ifeq ($(USE_HW_CRYPTO),1)
else
endif

#
# Define if system should support pointer authentication.
#
ifeq ($(PTRAUTH),1)
else
endif

#
# Define if system should support memory tagging extension.
#
ifeq ($(MEMTAG),1)
BUILDOPTS += -DMEMTAG
else
endif

#
# Add validate.c tests into the build. These symbols are for
# hypervisor internal state validation and can be called via
# the debugger.
#
ifeq ($(TESTS),1)
BUILDOPTS += -DTESTS=1
endif

#
# Use to allow remote debuggers to see secure guest internals.
# This is of course massively insecure development feature.
#
ifeq ($(GUESTDEBUG),1)
BUILDOPTS += -DGUESTDEBUG
endif

#
# Enable to collect per guest statistics on exit reasons for
# configuration and performance analysis.
#
ifeq ($(EXITLOG),1)
BUILDOPTS += -DEXITLOG
endif

#
# Enable to visualize guest mapping operation to console.
# Useful for example in early stages of platform porting.
#
ifeq ($(SPINNER),1)
BUILDOPTS += -DSPINNER
endif

# Disable kernel integrity check
ifeq ($(DISABLE_KIC),1)
BUILDOPTS += -DKIC_DISABLED
else
BUILDOPTS += -DKIC_ENABLED
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
export OPTS := $(BUILDOPTS)

#
# Use to make qemu wait for debugger connection, aka
# 'make gdb'
#
ifeq ($(DEBUGGER),1)
export DEBUGOPTS := -S -s
endif

#
# Poormans profiler session
#
ifeq ($(POORMAN),1)
export DEBUGOPTS := -s
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
