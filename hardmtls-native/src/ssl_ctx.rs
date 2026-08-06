//! OpenSSL `SSL_CTX` configuration for hardware-backed mTLS.
//!
//! This module manipulates raw OpenSSL `SSL_CTX*` pointers received from
//! Python's `ssl` module. We dynamically link against the same OpenSSL
//! that Python uses (via the `openssl-sys` crate) to avoid ABI mismatches.

use std::ffi::{c_char, c_void};

use crate::error::HardmtlsError;
use crate::SignCallback;

/// Configure an OpenSSL `SSL_CTX` with a client certificate and custom signing key.
///
/// This function:
/// 1. Parses the PEM-encoded certificate
/// 2. Loads the certificate into the `SSL_CTX`
/// 3. Creates a custom `EVP_PKEY` that delegates signing to `sign_func`
/// 4. Attaches the custom key to the `SSL_CTX`
///
/// # Safety
///
/// * `cert` must be a valid null-terminated C string containing PEM data.
/// * `ctx` must be a valid OpenSSL `SSL_CTX*` pointer.
/// * `sign_func` must remain valid for the lifetime of the SSL context.
#[allow(unsafe_code)]
pub unsafe fn configure_ssl_context(
    sign_func: SignCallback,
    cert: *const c_char,
    ctx: *mut c_void,
) -> Result<(), HardmtlsError> {
    // Validate inputs
    if cert.is_null() {
        return Err(HardmtlsError::SslError("cert pointer is null".into()));
    }
    if ctx.is_null() {
        return Err(HardmtlsError::SslError("SSL_CTX pointer is null".into()));
    }

    // TODO: Implement OpenSSL SSL_CTX manipulation:
    // 1. Parse cert PEM → X509
    // 2. SSL_CTX_use_certificate(ctx, x509)
    // 3. Create custom EVP_PKEY with sign_func callback
    // 4. SSL_CTX_use_PrivateKey(ctx, custom_key)

    let _ = sign_func; // Suppress unused warning until implemented

    Err(HardmtlsError::SslError("not yet implemented".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_uchar;
    use std::ptr;

    /// Dummy extern "C" sign function for testing.
    #[allow(unsafe_code)]
    unsafe extern "C" fn dummy_sign(
        _sig: *mut c_uchar,
        _sig_len: *mut usize,
        _tbs: *const c_uchar,
        _tbs_len: usize,
    ) -> std::ffi::c_int {
        1
    }

    #[test]
    fn null_cert_returns_error() {
        // SAFETY: Testing null input handling with a valid sign function pointer.
        #[allow(unsafe_code)]
        let result = unsafe {
            configure_ssl_context(
                dummy_sign,
                ptr::null(),
                // Non-null but invalid pointer — we never dereference it.
                ptr::null_mut::<c_void>().wrapping_add(1),
            )
        };
        assert!(matches!(
            result,
            Err(HardmtlsError::SslError(ref msg)) if msg == "cert pointer is null"
        ));
    }

    #[test]
    fn null_ctx_returns_error() {
        // SAFETY: Testing null input handling.
        #[allow(unsafe_code)]
        let result = unsafe {
            configure_ssl_context(
                dummy_sign,
                // Non-null but invalid pointer — we never dereference it.
                ptr::null::<c_char>().wrapping_add(1),
                ptr::null_mut(),
            )
        };
        assert!(matches!(
            result,
            Err(HardmtlsError::SslError(ref msg)) if msg == "SSL_CTX pointer is null"
        ));
    }

    #[test]
    fn both_null_returns_cert_error_first() {
        // SAFETY: Testing null input handling — cert is checked before ctx.
        #[allow(unsafe_code)]
        let result = unsafe { configure_ssl_context(dummy_sign, ptr::null(), ptr::null_mut()) };
        assert!(matches!(
            result,
            Err(HardmtlsError::SslError(ref msg)) if msg == "cert pointer is null"
        ));
    }
}
