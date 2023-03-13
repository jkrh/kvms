use core::arch::asm;

/// read cntfrq_el0
pub fn read_cntfrq_el0() -> u64 {
    let mut v: u64;

    unsafe {
        asm!(
            "mrs {0}, cntfrq_el0",
            out(reg) v,
            options(pure, nomem, nostack),
        );
    }
    v
}

/// read cntpct_el0
pub fn read_cntpct_el0() -> u64 {
    let mut v: u64;

    unsafe {
        asm!(
            "mrs {0}, cntpct_el0",
            out(reg) v,
            options(pure, nomem, nostack),
        );
    }
    v
}

/// wfe
pub fn wfe() {
    unsafe {
        asm!(
            "wfe",
            options(nomem, nostack),
        );
    }
}
