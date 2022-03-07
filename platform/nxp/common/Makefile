PROG := $(OBJDIR)/$(PLATFORM)/$(CHIPSET)/$(PRODUCT)/bl1
LIBNAME := lib$(PLATFORM).a

LINK := -T hyp.ld.S -e hyp_entrypoint
LDFLAGS := $(LINK) $(LDFLAGS)

AS_SOURCES := hyp_entrypoint.S
C_SOURCES := host_platform.c

include $(BASE_DIR)/core/common.mk
all: $(PROG).bin
