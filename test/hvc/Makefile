# Example (assuming compilation in docker environment)
# make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64 KERNEL_DIR=/kernel_dir

export OPTS := -g3 -Os

obj-m := kvms-t.o
kvms-t-y := kvms-test.o kvms-hvci.o

all:
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) \
	"KCFLAGS=$(OPTS)" modules

clean:
	make ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) -C $(KERNEL_DIR) M=$(PWD) clean
