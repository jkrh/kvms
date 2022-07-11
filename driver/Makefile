# ccflags-y := -Wp,-w
ifeq ($(DEBUG),1)
export OPTS := -g -O1 -DDEBUG
endif
TOOLDIR=$TOPDIR/buildtools
CROSS_COMPILE=aarch64-linux-gnu-

export PATH=$TOOLDIR/bin:$TOOLDIR/usr/bin:/bin:/usr/bin
export PKG_CONFIG_PATH=$TOOLDIR/usr/local/lib/x86_64-linux-gnu/pkgconfig


obj-m += hyp-drv.o

all:
	$(TOPDIR)/driver/gen_kaddr.sh $(KERNEL_DIR)
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) \
	"KCFLAGS=$(OPTS)" modules

clean:
	rm -f kaddr.h
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) clean
