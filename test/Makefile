# Build KVMS test modules
#
# Example (assuming compilation in docker environment)
# make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64 KERNEL_DIR=/kernel_dir

obj-m := hvc/ common/arm64/ blinding/demo/guest/ blinding/demo/host/
HOST_KERNEL_DIR := /kernel_dir

all:
	make -C $(HOST_KERNEL_DIR) M=$(PWD)

clean:
	make -C $(HOST_KERNEL_DIR) M=$(PWD) clean
