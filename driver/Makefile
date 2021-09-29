# ccflags-y := -Wp,-w
ifeq ($(DEBUG),1)
export OPTS := -g -O1 -DDEBUG
endif
KERNEL_DIR := $(PWD)/../oss/linux

obj-m += hyp-drv.o

all:
	$(PWD)/gen_kaddr.sh $(KERNEL_DIR)
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) \
	"KCFLAGS=$(OPTS)" modules

clean:
	rm -f kaddr.h
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) clean
