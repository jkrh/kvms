# SPDX-License-Identifier: GPL-2.0-only
AS_OBJ := $(patsubst $(notdir %.S),$(OBJDIR)/%.o,$(notdir $(AS_SOURCES)))
C_OBJ := $(patsubst %.c,$(OBJDIR)/%.o,$(notdir $(C_SOURCES)))
OBJS := $(C_OBJ) $(AS_OBJ)

COMMONLIBS := -lcore -lcommon -lplatform-common -lmbedcrypto -lmbedx509 -lmbedtls -larmv8crypto -lstdlib  -u print_gicdreg

ifeq ($(PLATFORM),virt)
LDLIBS := -l$(PLATFORM) $(COMMONLIBS)
else
LDLIBS := -l$(PLATFORM) -l$(PRODUCT) $(COMMONLIBS)
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

$(PROG).bin: $(PROG)
	$(vecho) [OBJCOPY] $@
	$(Q)$(OBJCOPY) -O binary $(PROG) $(PROG).bin

$(PROG): $(OBJS) $(OBJDIR)/$(LIBNAME) FORCE
	$(vecho) [LD] $@
	$(Q)$(LD) $(LDFLAGS) -lcore -o $(PROG) $(LDLIBS) -static

$(OBJDIR)/$(LIBNAME): $(OBJS)
	$(vecho) [AR] $@
	$(Q)$(AR) cru $(OBJDIR)/$(LIBNAME) $(OBJS)
	$(vecho) [RANLIB] $@
	$(Q)$(RANLIB) $(OBJDIR)/$(LIBNAME)

clean:
	@rm -rf $(OBJDIR)

FORCE:
