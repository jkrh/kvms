//!
//! bindings from C functions
//!

extern "C" {
    /// void *kr_malloc(size_t nbytes);
    pub fn kr_malloc(nbytes: usize) -> *mut ::core::ffi::c_void;
}
extern "C" {
    /// void kr_free(void *ap);
    pub fn kr_free(ap: *mut ::core::ffi::c_void);
}
extern "C" {
    /// void hyp_abort_plain(void);
    pub fn hyp_abort_plain();
}
