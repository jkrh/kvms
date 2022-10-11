PROG := $(OBJDIR)/$(PLATFORM)/hyp
DEVMEM := $(OBJDIR)/$(PLATFORM)/devmem
LIBNAME := lib$(PLATFORM).a
QEMU := qemu-system-aarch64

KERNEL := $(KERNEL_DIR)/arch/arm64/boot/Image
VMLINUX := $(KERNEL_DIR)/vmlinux
KERNEL_OPTS := root=/dev/vda1 console=ttyAMA0 mem=3G nokaslr loglevel=8 rw
WAYOUT := $(shell exec ip route get 1.1.1.1 | grep -oP 'src \K\S+')
PORT := 10022
DRIVE := -drive file=$(IMAGE),format=qcow2,if=sd,id=ubu-sd -device virtio-blk-device,drive=ubu-sd
USB := -device qemu-xhci -device usb-kbd -device usb-tablet
NETWORK := -device e1000,netdev=net0 -netdev user,id=net0,host=192.168.7.1,net=192.168.7.0/24,restrict=off,hostname=guest,hostfwd=tcp:$(WAYOUT):$(PORT)-192.168.7.2:22

SPICESOCK := /tmp/host
VDAGENT := -device virtio-serial-pci -device virtserialport,chardev=spicechannel0,name=spice.0 -chardev spicevmc,id=spicechannel0,name=vdagent
SPICEOPTS := unix=on,addr=$(SPICESOCK),disable-ticketing=on,image-compression=off,streaming-video=all,playback-compression=off,disable-agent-file-xfer=off

ifeq ($(DEBUGMMU),1)
QEMUDEBUGOPTS := guest_errors,unimp,mmu
else
QEMUDEBUGOPTS := guest_errors,unimp
endif
QEMUDEBUGLOG := -D $(BASE_DIR)/qemudebug.log

LINK := -T ld.out -Ttext=0x100001000
LDFLAGS := $(LDFLAGS) $(LINK)

AS_SOURCES := reset.S
C_SOURCES := host_platform.c

QEMUOPTS := --accel tcg,thread=multi -d $(QEMUDEBUGOPTS) $(QEMUDEBUGLOG) \
	    -machine virt,virtualization=on,secure=off,gic-version=3,highmem=off \
	    -cpu max,sve=off -m 4G -smp 4 -mem-path $(DEVMEM)                    \
	    $(DEBUGOPTS) -kernel $(KERNEL) -append '$(KERNEL_OPTS)'              \
	    $(NETWORK) $(USB) $(BOOTIMG)

ifeq ($(QEMUDEBUG),1)
QEMUCMD := gdb $(QEMU)-debug -ex "r $(QEMUOPTS) -serial stdio -display none"
else
QEMUCMD := $(QEMU) $(QEMUOPTS) -nographic
endif

ifeq ($(GRAPHICS),1)
QEMUCMD := $(QEMUCMD) -device virtio-gpu-gl-pci,id=gpu0 -display egl-headless -spice $(SPICEOPTS) $(VDAGENT)
endif

include $(BASE_DIR)/core/common.mk

all: $(PROG).bin

devmem: $(OBJDIR)/$(DTB)
	@dd if=/dev/zero of=$(DEVMEM) bs=1G count=4 > /dev/null 2>&1

run: devmem
	@echo "------------------------------------------------------------------------------------------"
ifeq ($(GRAPHICS),1)
	@echo "Graphics available at 'spice+unix://$(SPICESOCK)'"
endif
	@echo "Host ssh login is available via $(WAYOUT):$(PORT)"
	@echo "------------------------------------------------------------------------------------------"
	@rm -f $(SPICESOCK)
	@dd status=none bs=1G seek=3 conv=notrunc if=$(PROG).bin of=$(DEVMEM)
	@$(QEMUCMD)

gdb:
	@$(CROSS_COMPILE)gdb -ex "target remote localhost:1234" -ex "set confirm off"	\
		-ex "add-symbol-file $(PROG) 0x100001000" $(VMLINUX)

sign_guest:
	$(TOPDIR)/scripts/virt_update_guest_kernel_signature.sh -p  $(TOPDIR)/guest/keys/guest_image_priv.pem \
	-i $(BOOTIMG) -l $(TOPDIR)/guest/ic_loader/ic_loader -d home/ubuntu/vm/ubuntu20
