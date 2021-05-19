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
system memory and the guests can even be swapped out securely.

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
- Run 'make tools'. This will build all the tools required with right versions
  and install them into the 'buildtools' directory. This will also build the
  patched kernel under oss/linux.
- Download or assemble QEMU compatible arm64 linux image you wish to boot up.
  Script named 'scripts/make-bootimg.sh' may work as an example, it should work
  directly if you invoke it with superuser permissions.
- Set environment variable BOOTIMG to point to the image. Set PLATFORM=virt
  as well to tell the build system which target you are going for.
- Run 'make DEBUG=1' to build the hypervisor against the kernel under oss/linux
- 'make run' will run the host emulation
- 'make gdb' will run a target debugger session. You can hit breakpoints
  anywhere in the kernel and in the hypervisor. This implies that that 'run'
  target was invoked with 'make DEBUGGER=1 run' such that the QEMU was waiting
  for the debugger connection.
- Install more kvm virtual machines inside your host system emulation to see
  some more work the hypervisor is doing.
- Work with the kernel under oss/linux, hyp


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
1) Testing, testing, testing and debugging, especially on memory pressure
2) Analysis of the kvm callback functions in terms of whether or not further
   hardening is required
3) Protection of the critical shared memory blobs (vcpu, kvm and few others),
   don't allow active VM kvm/vcpu remaps
4) Proper 5.10 LTS kernel patch
5) Only allow kernel addresses (PHYS_OFFSET - (PHYS_OFFSET + RAM)) addresses
   to be stage2 mapped
6) Fuzz the guest input devices in order to prevent the easiest attacks for
   the malicious host.
