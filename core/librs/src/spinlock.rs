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
pub extern "C" fn spin_lock(_lock: *mut spinlock_t) {
    if CONFIG_ARM64_LSE == true {
        unsafe {
            // LSE atomics
            asm!("  stp     x0, x1, [sp, #-16]!",
                "   stp     x2, x3, [sp, #-16]!",
                "   mov     w2, #(1 << 16)",
                "   ldadda  w2, w3, [x0]",
                ".rept 3",
                "   nop",
                ".endr",
                // Did we get the lock?
                "   eor w1, w3, w3, ror #16",
                "   cbz w1, 3f",
                // No: spin on the owner. Send a local event to avoid missing
                // an unlock before the exclusive load.
                "   sevl",
                "2: wfe",
                "   ldaxrh  w2, [x0]",
                "   eor     w1, w2, w3, lsr #16",
                "   cbnz    w1, 2b",
                // We got the lock. Critical section starts here.
                "3:",
                "   ldp     x2, x3, [sp], #16",
                "   ldp     x0, x1, [sp], #16",
            );
        }
    } else {
        unsafe {
            // LL/SC atomics
            asm!("  stp     x0, x1, [sp, #-16]!",
                "   stp     x2, x3, [sp, #-16]!",
                "   prfm    pstl1strm, [x0]",
                "1: ldaxr   w3, [x0]",
                "   add     w1, w3, #(1 << 16)",
                "   stxr    w2, w1, [x0]",
                "   cbnz    w2, 1b",
                // Did we get the lock?
                "   eor w1, w3, w3, ror #16",
                "   cbz w1, 3f",
                // No: spin on the owner. Send a local event to avoid missing
                // an unlock before the exclusive load.
                "   sevl",
                "2: wfe",
                "   ldaxrh  w2, [x0]",
                "   eor     w1, w2, w3, lsr #16",
                "   cbnz    w1, 2b",
                // We got the lock. Critical section starts here.
                "3:",
                "   ldp     x2, x3, [sp], #16",
                "   ldp     x0, x1, [sp], #16",
            );
        }
    }
}

/// spin_unlock
#[no_mangle]
pub extern "C" fn spin_unlock(_lock: *mut spinlock_t) {
    if CONFIG_ARM64_LSE == true {
        unsafe {
            // LSE atomics
            asm!("  stp     x0, x1, [sp, #-16]!",
                "   mov     w1, #1",
                "   staddlh w1, [x0]",
                ".rept 1",
                "   nop",
                ".endr",
                "   ldp     x0, x1, [sp], #16",
            );
        }
    } else {
        unsafe {
            // LL/SC atomics
            asm!("  stp     x0, x1, [sp, #-16]!",
                "   ldrh    w1, [x0]",
                "   add     w1, w1, #1",
                "   stlrh   w1, [x0]",
                "   ldp     x0, x1, [sp], #16",
            );
        }
    }
}
