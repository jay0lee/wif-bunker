//! End-to-end test for the hardmTLS OpenSSL Provider pipeline.
// Run with: cargo test --test provider_e2e -- --nocapture
#![allow(missing_docs)]

use std::ffi::{c_int, c_uchar};

/// Dummy sign function that writes zeros.
#[allow(unsafe_code)]
#[allow(dead_code)]
unsafe extern "C" fn dummy_sign(
    sig: *mut c_uchar,
    sig_len: *mut usize,
    _tbs: *const c_uchar,
    tbs_len: usize,
) -> c_int {
    if sig.is_null() {
        unsafe { *sig_len = 256 };
        return 1;
    }
    let len = tbs_len.min(256);
    unsafe {
        std::ptr::write_bytes(sig, 0, len);
        *sig_len = len;
    }
    1
}

fn dump_openssl_errors() {
    #[allow(unsafe_code)]
    unsafe {
        loop {
            let err = openssl_sys::ERR_get_error();
            if err == 0 {
                break;
            }
            let reason = openssl_sys::ERR_reason_error_string(err);
            if reason.is_null() {
                eprintln!("    OpenSSL error code: {err}");
            } else {
                let msg = std::ffi::CStr::from_ptr(reason);
                eprintln!("    OpenSSL error: {msg:?}");
            }
        }
    }
}

#[test]
fn provider_registers_and_creates_pkey() {
    // Step 1: Register the provider.
    eprintln!("Step 1: Registering provider...");
    let result = hardmtls::provider::register_provider();
    eprintln!("  register_provider result: {result:?}");
    assert!(result.is_ok(), "register_provider failed: {result:?}");

    // Step 2: Try EVP_PKEY_CTX_new_from_name.
    eprintln!("Step 2: Creating EVP_PKEY_CTX...");
    #[allow(unsafe_code)]
    let pkey_ctx = unsafe {
        openssl_sys::EVP_PKEY_CTX_new_from_name(
            std::ptr::null_mut(),
            c"RSA".as_ptr(),
            c"provider=hardmtls,hardmtls.sign=yes".as_ptr(),
        )
    };
    eprintln!("  EVP_PKEY_CTX: {pkey_ctx:?}");

    if pkey_ctx.is_null() {
        eprintln!("  EVP_PKEY_CTX_new_from_name failed!");
        dump_openssl_errors();
        panic!("EVP_PKEY_CTX_new_from_name failed");
    }

    // Step 3: fromdata_init.
    eprintln!("Step 3: EVP_PKEY_fromdata_init...");
    #[allow(unsafe_code)]
    let rc = unsafe { openssl_sys::EVP_PKEY_fromdata_init(pkey_ctx) };
    eprintln!("  fromdata_init rc: {rc}");

    if rc != 1 {
        dump_openssl_errors();
    }
    assert_eq!(rc, 1);

    // Clean up.
    #[allow(unsafe_code)]
    unsafe {
        openssl_sys::EVP_PKEY_CTX_free(pkey_ctx);
    }
    eprintln!("All steps passed!");
}
