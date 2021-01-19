# ccflags-y := -Wp,-w
ifeq ($(DEBUG),1)
export OPTS := -g -O0 -DDEBUG
endif

obj-m += hyp-drv.o

all: kaddr.h
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) \
	"KCFLAGS=$(OPTS)" modules

kaddr.h:
	$(PWD)/gen_kaddr.sh $(KERNEL_DIR)

clean:
	rm -f kaddr.h
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) clean
