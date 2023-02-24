PROGNAME := bl1
PROG := $(OBJDIR)/$(PLATFORM)/$(CHIPSET)/$(PRODUCT)/$(PROGNAME)
LIBNAME := lib$(PLATFORM).a

LINK := -T hyp.ld.S -e hyp_entrypoint
LDFLAGS := $(LINK) $(LDFLAGS)

AS_SOURCES := hyp_entrypoint.S
C_SOURCES := host_platform.c

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

all: $(PROG).bin
