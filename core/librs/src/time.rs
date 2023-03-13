use crate::reg;

const SECONDS:u64       = 1;
#[allow(dead_code)]
const MILLISECONDS:u64  = 1_000;
const MICROSECONDS:u64  = 1_000_000;
#[allow(dead_code)]
const NANOSECONDS:u64   = 1_000_000_000;

/// struct timeval conforming to POSIX.1-2001 and later.
#[repr(C)]
pub struct timeval {
    tv_sec: u64,
    tv_usec: u64,
}

impl timeval {
    fn init(&mut self) {
        self.tv_sec = 0;
        self.tv_usec = 0;
    }

    fn set_value(&mut self, tv: &timeval) {
        self.tv_sec = tv.tv_sec;
        self.tv_usec = tv.tv_usec;
    }
}

static mut BOOT_TS: timeval = timeval { tv_sec:0, tv_usec:0 };

fn __gettimeofday(tv: &mut timeval) {
    let cntptval_org:u64;
    let cntfrq_org:u64;
    let mut val:u64;

    tv.init();

    cntfrq_org = reg::read_cntfrq_el0();
    cntptval_org = reg::read_cntpct_el0();

    val = cntptval_org * MICROSECONDS;
    val = val / cntfrq_org;
    tv.tv_usec = val;

    val = cntptval_org * SECONDS;
    val = val / cntfrq_org;
    tv.tv_sec = val;
}

/// read current time since boot
pub fn _gettimeofday(tv: &mut timeval) {
    __gettimeofday(tv);

    unsafe {
        if BOOT_TS.tv_usec == 0 {
            BOOT_TS.set_value(&tv);
        }
        if tv.tv_usec < BOOT_TS.tv_usec {
            BOOT_TS.set_value(&tv);
        }
        tv.tv_usec -= BOOT_TS.tv_usec;
        tv.tv_sec -= BOOT_TS.tv_sec;
    }
}

/// sleep during usecs
pub fn _usleep(usec: u64) {
    let mut now = timeval { tv_sec: 0, tv_usec: 0 };
    let mut then = timeval { tv_sec: 0, tv_usec: 0 };

    _gettimeofday(&mut now);
    then.set_value(&now);
    then.tv_usec += usec;

    while now.tv_usec < then.tv_usec {
        reg::wfe();
        _gettimeofday(&mut now);
    }
}
