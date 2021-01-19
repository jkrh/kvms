******************************************************************************
KVM compatible ARM64 hypervisor
******************************************************************************

This project is a template of a hypervisor that can function outside of the
linux kernel protecting the host kernel, but it can also enable support for
the KVM virtual machines through requests initiated by the host kernel KVM
API.

The project also attempts to take a step forward from regular KVM security
levels by placing less trust in the host kernel. The host belongs in the TCB
only during the guest initialization phase such that the guest stays secure
even if the host is later compromised as a result of a runtime vulnerability.
When configured to do so, the hypervisor will unmap the KVM guests from the
host kernel memory. The goal is to try to make sure that even a compromised
host kernel would not be able to access the guest memory beyond the allowed
areas such as the virtio shared memory. We try to do this while a single
host kernel is still responsible for the allocation and deallocation of the
entire host machine physical RAM space for maximum utilization of the memory
in embedded systems. There is no need to pin guest memory permanently in the
system memory.

To accomplish the above mentioned duties the hypervisor takes ownership of
the EL2 exception vector, the EL2 stage 1 translation table and the stage 2
translation table of the lower ELs. We have attempted to keep changes to the
kvm kernel code minimal, only adding handful of hooks into it. ~95% of the
kvm code is intact and the hypervisor calls it directly as it needs the
guests to execute.

The current state of the code is that the regular KVM guests execute somewhat
reliably on multiple ARM64 systems. The 'host blinding' feature does run, but
all in all it's still work in progress and may crash and burn at places
especially if you play with untested QEMU cmdline. The required kernel patch
currently provided under patches/ is a mock-up and it will soon be cleaned up
for 5.10 LTS releases, mostly moving the required new functions into a
separate c file.

QEMU host emulation based development environment is provided in the source
tree and it operates on top of the 'virt' machine. Both the kernel and the
hypervisor can be stepped through via a relatively comfortable environment.


Building and running on QEMU:
-----------------------------
- download current linux kernel, git tag is kvmarm-5.6
- apply patches/0001-*5.6*.patch to the kernel
- download or assemble a .qcow2 linux image you wish to boot up
- build the kernel:
  make -j16 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig Image modules
- build the hyp:
  export KERNEL_DIR=<kernel top level dir>
  export PLATFORM=virt
  export BOOTIMG=<image you want to boot as the host>
  make
- make run will run the host emulation
- make gdb will run a target debugger session. You can hit breakpoints anywhere
  in the kernel and in the hypervisor. This implies that that 'run' target was
  invoked with 'make DEBUGGER=1 run'


Testing on the virt platform:
-------------------------------------
- usage:
  ./scripts/module-compile.sh \
  && make test
- clones and compiles kernel and qemu
- compiles hyp
- downloads BOOTIMG
- performs small module-test


SHORT TERM TODO
----------------
1) Testing, testing, testing and debugging
2) Finishing the merkle tree / hash list / for the guest paging. The code in
   the repo is entirely untested and not currently in use.
3) Analysis of the kvm callback functions in terms of whether or not further
   hardening is required
4) Protection of the critical shared memory blobs (vcpu, kvm and few others)
5) Testing the behavior on the host memory pressure
6) Proper 5.10 LTS kernel patch
7) Some HVC calls need to be made 'fused', ie available only once during the
   bootup.
8) HVC kernel callback interface should be hardened and only function entry
   points must be callable.
