#  aarch64-linux-gnu-objcopy -I binary -B aarch64 -O elf64-littleaarch64 image.png image.png.o_shipped
#  aarch64-linux-gnu-objcopy -O binary image.png image.png.o_shipped
export BASE_DIR := /hyp

# ccflags-y := -I$(BASE_DIR)/buildtools/usr/include
# make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64

export OPTS := -g3 -Os --verbose
ccflags-y := -I$(src)/../../../common/arm64

GUEST_KERNEL_DIR := $(BASE_DIR)/oss/linuxg

obj-m := demo-g.o
demo-g-y := demo-guest.o image.png.o

all:
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(GUEST_KERNEL_DIR) M=$(PWD) \
	"KCFLAGS=$(OPTS)" modules

clean:
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(GUEST_KERNEL_DIR) M=$(PWD) clean
