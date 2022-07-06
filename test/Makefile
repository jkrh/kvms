# Build KVMS test modules
#
# Example (assuming compilation in docker environment)
# make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64 KERNEL_DIR=/kernel_dir

obj-m := hvc/ common/arm64/

all:
	make -C $(KERNEL_DIR) M=$(PWD)

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
