# SPDX-License-Identifier: GPL-2.0-only
AS_OBJ := $(patsubst $(notdir %.S),$(OBJDIR)/%.o,$(notdir $(AS_SOURCES)))
C_OBJ := $(patsubst %.c,$(OBJDIR)/%.o,$(notdir $(C_SOURCES)))
OBJS := $(C_OBJ) $(AS_OBJ)

COMMONLIBS := -lcore -lcommon -lplatform-common -lmbedcrypto -lmbedx509 \
		-lmbedtls -larmv8crypto -lstdlib -lkvms_rs -u print_gicdreg
COMMON_ARLIBS := $(OBJDIR)/libcore.a \
		 $(OBJDIR)/libcommon.a \
		 $(OBJDIR)/libplatform-common.a \
		 $(MBEDDIR)/libmbedcrypto.a \
		 $(MBEDDIR)/libmbedx509.a \
		 $(MBEDDIR)/libmbedtls.a \
		 $(OBJDIR)/libarmv8crypto.a \
		 $(OBJDIR)/libstdlib.a

ifeq ($(PLATFORM),virt)
LDLIBS ?= -l$(PLATFORM) $(COMMONLIBS)
ARLIBS ?= $(OBJDIR)/lib$(PLATFORM).a $(COMMON_ARLIBS)
else
LDLIBS ?= -l$(PLATFORM) -l$(PRODUCT) $(COMMONLIBS)
ARLIBS ?= $(OBJDIR)/lib$(PLATFORM).a $(OBJDIR)/lib$(PRODUCT).a $(COMMON_ARLIBS)
endif

.PHONY: clean run gdb

ifeq ("$(V)","1")
Q :=
vecho = @true
else
Q := @
vecho = @echo
endif

SPLINTOPTS := -unrecog -nullret -boolops -fileextensions -badflag \
	 +longunsignedintegral
SPLINT := splint $(SPLINTOPTS)

$(OBJDIR)/%.o: %.S
	$(vecho) [CC] $@
	$(Q)$(CC) $(ASFLAGS) -o $@ -c $<

$(OBJDIR)/%.o: $(CORE_DIR)/%.S
	$(vecho) [CC] $@
	$(Q)$(CC) $(CFLAGS) -o $@ -c $<

$(OBJDIR)/%.o: %.c
ifeq ("$(L)","1")
	-$(SPLINT) $(CFLAGS) -o $@ -c $<
endif
	$(vecho) [CC] $@
	$(Q)$(CC) $(CFLAGS) -o $@ -c $<

$(OBJDIR)/%.o: $(CORE_DIR)/%.c
ifeq ("$(L)","1")
	-$(SPLINT) $(CFLAGS) -o $@ -c $<
endif
	$(vecho) [CC] $@
	$(Q)$(CC) $(CFLAGS) -o $@ -c $<

$(OBJDIR)/$(LIBNAME): $(OBJS)
	$(vecho) [AR] $@
	$(Q)$(AR) rcsTP $(OBJDIR)/$(LIBNAME) $(OBJS)

clean:
	@rm -rf $(OBJDIR) $(PROG) *.elf *.o *.bin

PHONY += FORCE
FORCE:
