# make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64
export BASE_DIR := /hyp

export OPTS := -g3 -Os
KERNEL_DIR := /kernel_dir

obj-m := demo-h.o
demo-h-y := demo-host.o

all:
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) \
	"KCFLAGS=$(OPTS)" modules

clean:
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) clean
