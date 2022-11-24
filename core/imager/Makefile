LZ4DIR := $(BASE_DIR)/oss/lz4
PHONY := all clean

include $(BASE_DIR)/core/hosttools.mk

CTOOL_CFLAGS := $(CFLAGS) -I$(LZ4DIR)/lib -L$(LZ4DIR)/lib -llz4
LOADR_INCLUDES := -I$(BASE_DIR)/core -I$(BASE_DIR)/stdlib
LOADR_LIBS := -L$(OBJDIR) -lcore -lstdlib
LOADR_CFLAGS := $(CFLAGS) -static -ffreestanding -fno-hosted -Wno-main -mstrict-align \
		-march=armv8-a+nosimd -mgeneral-regs-only -nostdlib -fpic -fPIC \
		-fpie --sysroot=$(TOOLDIR) $(LOADR_INCLUDES) $(LOADR_LIBS)
LOAD_LDFLAGS :=	-Wl,-T./ld.out -Wl,-Ttext=0xC0081000
LOADR_CSOURCES := lmain.c

all: hyp-loader.bin

lz4:
	$(MAKE) -C $(LZ4DIR) default

comptool: lz4
	@$(CC) -o $@ comptool.c $(LZ4DIR)/lib/lz4.c $(LZ4DIR)/lib/lz4hc.c $(CTOOL_CFLAGS)

hyp-binary.o: comptool
	@./comptool $(OBJDIR)/$(PLATFORM)/$(PROG)*.bin $@.lz4
	@$(CROSS_COMPILE)ld -r -b binary -o $@ $@.lz4

lreset.o:
	@$(CROSS_COMPILE)gcc -o $@ -c lreset.S $(LOADR_CFLAGS)

hyp-loader: hyp-binary.o lreset.o
	@$(CROSS_COMPILE)gcc -o $@ lmain.c $(LOADR_CFLAGS) $(LOAD_LDFLAGS)

hyp-loader.bin: hyp-loader
	@$(CROSS_COMPILE)objcopy -O binary hyp-loader hyp-loader.bin

clean:
	$(MAKE) -C $(LZ4DIR) clean
	@rm -f comptool hyp-binary hyp-loader *.bin *.o *.lz4
