LZ4DIR := $(BASE_DIR)/oss/lz4
ifeq ($(PLATFORM),virt)
OUTDIR := $(OBJDIR)/$(PLATFORM)
else
OUTDIR := $(OBJDIR)/$(PLATFORM)/$(CHIPSET)/$(PRODUCT)
endif

ifneq (,$(wildcard $(BASE_DIR)/platform/$(PLATFORM)/common))
COMMON_DIR := /common
endif
PROG := $(shell cat '$(BASE_DIR)/platform/$(PLATFORM)$(COMMON_DIR)/Makefile' \
        | sed -ne 's/^PROG := //p' | sed 's/.*\///')

$(info Creating compressed image for : $(PROG).bin )

export OUTDIR := $(OUTDIR)
PHONY := all clean

include $(BASE_DIR)/core/hosttools.mk

CTOOL_CFLAGS := $(CFLAGS) -I$(LZ4DIR)/lib -L$(LZ4DIR)/lib -llz4
LOADR_INCLUDES := -I$(BASE_DIR)/core -I$(BASE_DIR)/stdlib -I$(OUTDIR)
LOADR_LIBS := -L$(OBJDIR) -L$(OUTDIR) -lcore -lstdlib
LOADR_CFLAGS := $(CFLAGS) -static -ffreestanding -fno-hosted -Wno-main -mstrict-align \
		-march=armv8-a+nosimd -mgeneral-regs-only -nostdlib -fpic -fPIC \
		-fpie --sysroot=$(TOOLDIR) $(LOADR_INCLUDES) $(LOADR_LIBS) \
		-DUNSAFE_LZ4
LOAD_LDFLAGS :=	-Wl,-T./ld.out -Wl,-Ttext=0xC0081000
LOADR_CSOURCES := lmain.c

all: $(OUTDIR)/hyp-loader.bin

$(OUTDIR)/lz4:
	$(MAKE) -C $(LZ4DIR) default

$(OUTDIR)/comptool: $(OUTDIR)/lz4
	@$(CC) -o $@ comptool.c $(LZ4DIR)/lib/lz4.c $(LZ4DIR)/lib/lz4hc.c $(CTOOL_CFLAGS)

$(OUTDIR)/hyp-binary.o: $(OUTDIR)/comptool
	@$< $(OUTDIR)/$(PROG).bin $@.lz4
	@$(CROSS_COMPILE)ld -r -b binary -o $@ $@.lz4

$(OUTDIR)/lreset.o:
	@$(CROSS_COMPILE)gcc -o $@ -c lreset.S $(LOADR_CFLAGS)

$(OUTDIR)/lsymbols.h: $(OUTDIR)/hyp-binary.o
	$(BASE_DIR)/core/imager/genlsymheader.sh

$(OUTDIR)/hyp-loader: $(OUTDIR)/lsymbols.h $(OUTDIR)/lreset.o
	@$(CROSS_COMPILE)gcc -o $@ lmain.c $(LOADR_CFLAGS) $(LOAD_LDFLAGS)

$(OUTDIR)/hyp-loader.bin: $(OUTDIR)/hyp-loader
	@$(CROSS_COMPILE)objcopy -O binary $< $@

clean:
	$(MAKE) -C $(LZ4DIR) clean
