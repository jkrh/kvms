// SPDX-License-Identifier: GPL-2.0

//!
//! Allocator support.
//!
//! GlobalAlloc trait is implemented to use the heap area prepared
//! by C code. This can be moved to rust later as the codes grow in rust.
//!
//! #[alloc_error_handler] attribute
//! link: <https://github.com/rust-lang/rust/issues/66740>
//! #![feature(default_alloc_error_handler)]
//! link: <https://github.com/rust-lang/rust/issues/66741>
//!
//! # Example
//! ```
//! use alloc::vec::Vec;
//! let mut v = Vec::new();
//! v.push(1);
//! ```

use core::alloc::{GlobalAlloc, Layout};

use crate::bindings;

struct HypAllocator;

unsafe impl GlobalAlloc for HypAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { bindings::kr_malloc(layout.size()) as *mut u8 }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe {
            bindings::kr_free(ptr as *mut core::ffi::c_void);
        }
    }
}

#[global_allocator]
static HEAP: HypAllocator = HypAllocator;
