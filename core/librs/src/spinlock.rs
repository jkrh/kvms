// SPDX-License-Identifier: GPL-2.0

//!
//! ticket spinlock rust implementation.
//!
//! Copyright (C) 2023 Katim LLC
//! Author: Keuno Park
//!
//! This code is based on the kernel's ticket spinlock implementation which was:
//! Copyright (C) 2012 ARM Ltd.
//!
//! # Example
//! ```
//! use crate::{spinlock, spinlock_t};
//! let mut lock = spinlock::default();
//! spin_lock(&mut lock);
//! ... critical section ...
//! spin_unlock(&mut lock);
//! ```

#![allow(missing_docs)]

use core::arch::asm;

/// union spinlock definition
#[repr(C)]
#[derive(Copy, Clone)]
pub union spinlock {
    pub __val: u32,
    pub s: spinlock__bindgen_ty_1,
    _bindgen_union_align: u32,
}
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct spinlock__bindgen_ty_1 {
    pub owner: u16,
    pub next: u16,
}
impl Default for spinlock {
    fn default() -> Self {
        unsafe { ::core::mem::zeroed() }
    }
}

#[allow(non_camel_case_types)]
pub type spinlock_t = spinlock;

/// NOTE: The use of ARMv8.1 LSE(Large System Extensions) is disabled.
/// This needs to be set to true for better performance but, enabling LSE
/// on Rust is still unknown. Currently making this 'true' will cause
/// a compile error.
const CONFIG_ARM64_LSE: bool = false;

/// spin_lock
#[no_mangle]
pub extern "C" fn spin_lock(lock: *mut spinlock_t) {
    let mut _tmp: u32;
    let mut _ptr = unsafe { core::ptr::addr_of!((*lock).__val) };
    let mut _owner = unsafe { core::ptr::addr_of!((*lock).s.owner) };
    let mut lockval = spinlock::default();
    let mut newval = spinlock::default();

    if CONFIG_ARM64_LSE == true {
        unsafe {
            // LSE atomics
            asm!("  mov     {2:w}, #(1 << 16)",
                "   ldadda  {2:w}, {0:w}, [{3:x}]",
                ".rept 3",
                "   nop",
                ".endr",
                // Did we get the lock?
                "   eor {1:w}, {0:w}, {0:w}, ror #16",
                "   cbz {1:w}, 3f",
                // No: spin on the owner. Send a local event to avoid missing
                // an unlock before the exclusive load.
                "   sevl",
                "2: wfe",
                "   ldaxrh  {2:w}, [{4:x}]",
                "   eor     {1:w}, {2:w}, {0:w}, lsr #16",
                "   cbnz    {1:w}, 2b",
                // We got the lock. Critical section starts here.
                "3:",
                inout(reg) lockval.__val,
                inout(reg) newval.__val,
                out(reg) _tmp,
                inout(reg) _ptr,
                inout(reg) _owner,
            );
        }
    } else {
        unsafe {
            // LL/SC atomics
            asm!("  prfm    pstl1strm, [{3:x}]",
                "1: ldaxr   {0:w}, [{3:x}]",
                "   add     {1:w}, {0:w}, #(1 << 16)",
                "   stxr    {2:w}, {1:w}, [{3:x}]",
                "   cbnz    {2:w}, 1b",
                // Did we get the lock?
                "   eor {1:w}, {0:w}, {0:w}, ror #16",
                "   cbz {1:w}, 3f",
                // No: spin on the owner. Send a local event to avoid missing
                // an unlock before the exclusive load.
                "   sevl",
                "2: wfe",
                "   ldaxrh  {2:w}, [{4:x}]",
                "   eor     {1:w}, {2:w}, {0:w}, lsr #16",
                "   cbnz    {1:w}, 2b",
                // We got the lock. Critical section starts here.
                "3:",
                inout(reg) lockval.__val,
                inout(reg) newval.__val,
                out(reg) _tmp,
                inout(reg) _ptr,
                inout(reg) _owner,
            );
        }
    }
}

/// spin_unlock
#[no_mangle]
pub extern "C" fn spin_unlock(lock: *mut spinlock_t) {
    let mut _tmp: u64 = 0;
    let mut _owner = unsafe { core::ptr::addr_of!((*lock).s.owner) };

    if CONFIG_ARM64_LSE == true {
        unsafe {
            // LSE atomics
            asm!("  mov     {1:w}, #1",
                "   staddlh {1:w}, [{0:x}]",
                ".rept 1",
                "   nop",
                ".endr",
                inout(reg) _owner,
                inout(reg) _tmp,
                options(nostack),
            );
        }
    } else {
        unsafe {
            // LL/SC atomics
            asm!("  ldrh    {1:w}, [{0:x}]",
                "   add     {1:w}, {1:w}, #1",
                "   stlrh   {1:w}, [{0:x}]",
                inout(reg) _owner,
                inout(reg) _tmp,
                options(nostack),
            );
        }
    }
}
