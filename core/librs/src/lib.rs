#![no_std]
#![no_main]

//! kvms_rs crate

/// set global_allocator
pub mod alloc;
/// C api bindings
pub mod bindings;
/// arch specific registers access
pub mod reg;
/// common api for getting time and calling usleep
pub mod time;

use time::timeval;

/// gettimeofday thin wrapper for C interface
/// FIXME: this does not conform to POSIX.1-2001
#[no_mangle]
pub extern "C" fn gettimeofday(tv: &mut timeval) -> i32 {
    time::_gettimeofday(tv);
    0
}

/// usleep thin wrapper for C interface
#[no_mangle]
pub extern "C" fn usleep(usec: u64) -> i32 {
    time::_usleep(usec);
    0
}

/// panic handler
/// # Example
/// '''
/// panic!();
/// '''
#[panic_handler]
fn hyp_panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { bindings::hyp_abort_plain(); }
    loop {}
}
