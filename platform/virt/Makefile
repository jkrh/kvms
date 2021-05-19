PROG := $(OBJDIR)/$(PLATFORM)/hyp
DEVMEM := $(OBJDIR)/$(PLATFORM)/devmem
LIBNAME := lib$(PLATFORM).a
QEMU := qemu-system-aarch64

KERNEL := $(KERNEL_DIR)/arch/arm64/boot/Image
VMLINUX := $(KERNEL_DIR)/vmlinux
KERNEL_OPTS := root=/dev/vda2 console=ttyAMA0 mem=3G nokaslr loglevel=8 rw
WAYOUT := $(shell exec ip route get 1.1.1.1 | grep -oP 'src \K\S+')
PORT := 10022
DRIVE := -drive file=$(IMAGE),format=qcow2,if=sd,id=ubu-sd -device virtio-blk-device,drive=ubu-sd
NETWORK := -device e1000,netdev=net0 -netdev user,id=net0,host=192.168.7.1,net=192.168.7.0/24,restrict=off,hostname=guest,hostfwd=tcp:$(WAYOUT):$(PORT)-192.168.7.2:22
QEMUDEBUGOPTS := guest_errors,unimp

LINK := -T ld.out -Ttext=0x100001000
LDFLAGS := $(LDFLAGS) $(LINK)

AS_SOURCES := reset.S
C_SOURCES := host_platform.c

QEMUOPTS := --accel tcg,thread=multi -d $(QEMUDEBUGOPTS) \
	    -machine virt,virtualization=on,secure=off,gic-version=3,highmem=off \
	    -cpu max,sve=off -m 4G -smp 4 -mem-path $(DEVMEM)                    \
	    $(DEBUGOPTS) -kernel $(KERNEL) -append '$(KERNEL_OPTS)'              \
	    $(NETWORK) $(BOOTIMG)

ifeq ($(QEMUDEBUG),1)
QEMUCMD := gdb $(QEMU)-debug -ex "r $(QEMUOPTS) -serial stdio -display none"
else
QEMUCMD := $(QEMU) $(QEMUOPTS) -nographic
endif

include $(BASE_DIR)/core/common.mk

all: $(PROG).bin

devmem: $(OBJDIR)/$(DTB)
	@dd if=/dev/zero of=$(DEVMEM) bs=1G count=4 > /dev/null 2>&1

run: devmem
	@dd status=progress bs=1G seek=3 conv=notrunc if=$(PROG).bin of=$(DEVMEM)
	@echo "Host ssh login is available via $(WAYOUT):$(PORT)"
	@$(QEMUCMD)

gdb:
	@$(CROSS_COMPILE)gdb -ex "target remote localhost:1234" -ex "set confirm off"	\
		-ex "add-symbol-file $(PROG) 0x100001000" $(VMLINUX)
