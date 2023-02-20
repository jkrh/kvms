# SPDX-License-Identifier: GPL-2.0-only

PROG := ic_loader
LIBNAME := libic.a

AS_SOURCES := start.S
C_SOURCES := ic_loader.c

override SANITIZER_OPTS := -fno-sanitize=all
override CFLAGS := -FPIC -I$(CORE_DIR) --sysroot=$(TOOLDIR)
override LDFLAGS := -static -T ld.out -L$(BASE_DIR)/.objs
override LDLIBS := -lic -lstdlib

all: $(PROG).hex

$(PROG).bin: $(PROG)
	$(vecho) [OBJCOPY] $@
	$(Q)$(OBJCOPY) -O binary $(PROG) $(PROG).bin

$(PROG).hex: $(PROG)
	$(vecho) [OBJCOPY] $@
	mkdir -p  $(CORE_DIR)/generated/
	$(Q)$(OBJCOPY) -O binary $(PROG) $(PROG).bin
	cat $(PROG).bin | hexdump -ve '"0x%08X,"' > $(CORE_DIR)/generated/$(PROG).hex

$(PROG): $(OBJS) $(OBJDIR)/$(LIBNAME) FORCE
	$(vecho) [LD] $@
	$(Q)$(LD) $(LDFLAGS) -o $(PROG) $(LDLIBS) -static

include $(BASE_DIR)/core/common.mk
