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

The current state of the code is that the regular KVM guests execute reliably
on multiple ARM64 systems. There are two 'host blinding' (aka detach the
guest from the host memory) models implemented in the code:
1) 'Memory encryption' model (used by AMD SEV/Intel TDX/IBM S390) with the HW
   support for the memory encryption) where the guests inform the hypervisor
   about the pages that were allocated for the guest <-> host communications.
   This model requires patching the guest kernel. There is a sample patch
   provided in the patches/ dir and it's based on extending the ARM64
   architecture by claiming that it supports 'memory encyption' and running
   through the same hooks as the other architectures with the actual memory
   encryption support.
2) A model where we trap to the hypervisor when the host touches the guest
   memory. This model does not require patching the guest kernel but it is
   somewhat less secure. During the trap prior to mapping the page back to
   the host the hypervisor checks that:
   - The trapping host process is a known virtual machine QEMU process in
     the host and that it is a known client with a correct run state.
   - The memory being mapped back is dedicated guest device memory (not RAM).
   - We are still in the middle of the quest kernel initialization phase.

There is an option to extend the model to take the host entirely out of the
TCB but this work is yet to be done. This involves adding an image signature
check callback to the QEMU bootloader. After the QEMU has loaded (as in
placed them in the memory for real) the relevant images that are about to be
invoked, the hypervisor has to be invoked to verify them. Also note that the
emulated hardware provided by the QEMU running inside the host have to be
considered not be part of the TCB; in other words, the kernel will have all
new attack vector as all host provided virtual devices can attempt to attack
the guest.

QEMU host emulation based development environment is provided in the source
tree and it operates on top of the 'virt' machine. The host kernel and the
hypervisor can be stepped through via a relatively comfortable environment.
The KVM quest debugging with gdb works on the hardware but exposes a bug in
QEMU we have not investigated: setting hardware breakpoints makes the
execution extremely slow (instruction execution becomes heavier and heavier
over time if a breakpoint is set). Stepping works fine.


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


Guest support
------------------
- All QEMU boards, 'virt' for the host emulation / sdk
- Preliminary 'ranchu' support for Android but no support for 'Android pipe'
- Android via 'virt' emulation to run arm64 cuttlefish. Given the mesa/gallium
  driver stack even the Virtio-GPU may run on some systems.


Secure swapping
-----------------
- The support is experimental. High level logic is as follows:
  - When the linux mm evicts a clean page, we measure it (sha256) to make sure
    it can't change while the vm doesn't own it. Besides the actual page data,
    we also measure the page permissions so that the page cannot change from RO
    to RW once being reloaded.
  - When the mm evicts a dirty page, we encrypt AND measure it on its way to the
    swap. We don't use the authenticated encryption as the measurement code has
    to be in place anyway to handle the clean / RO pages.

Now, be warned, there are some rough corners. When a page has migrated away
from the host, the host mm looses visibility to the page state and all the
software and even the hardware managed dirty state it is able to perform go out
of sync. Thus, the mm might not know what to sync to the media when the page
eventually finds its way back to the host. Moreover, we also make the pages
dirty behind the scenes every time we encrypt a writable guest page, but we do
try to mark our changes in the qemu dirty log when the logging is active. It is
yet to be sorted what the mm does when it scans an area where the pages may seem
clean, but yet they might not be. Similar virtualization solutions (Intel TDX
and AMD SEV) probably don't suffer from this potential pithole as the mm remains
up to date about the page state, encrypted or not.


Migration support TODO
-----------------------
- Dirty bitmask handling (partly done)
- Key export / import
- ??


SHORT TERM TODO
----------------
1) Memory pressure testing
2) VCPU register save in the hyp
3) Hardened guest config
4) Migration support
5) Finish android hardware support (32bit environment goes SIGILL)
6) Translation code unit test: make sure 'at' and 'pt_walk' agree about the
   system state
