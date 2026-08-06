//! OpenSSL `SSL_CTX` configuration for hardware-backed mTLS.
//!
//! This module manipulates raw OpenSSL `SSL_CTX*` pointers received from
//! Python's `ssl` module. We dynamically link against the same OpenSSL
//! that Python uses (via the `openssl-sys` crate) to avoid ABI mismatches.
//!
//! # Implementation Status
//!
//! The approach for creating custom signing keys depends on the target
//! OpenSSL version. We target OpenSSL 4.0 LTS (current) best-practice
//! interfaces. The legacy `RSA_METHOD` / `EC_KEY_METHOD` / `ENGINE` APIs
//! are deprecated in OpenSSL 3.x and removed in 4.0. The replacement is
//! the OpenSSL Provider API or potentially switching to BoringSSL/aws-lc
//! which natively support `SSL_CTX_set_private_key_method`.

use std::ffi::{c_char, c_void, CStr};
use std::ptr;

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
/// * `ctx` must be a valid OpenSSL `SSL_CTX*` pointer from Python's `ssl` module.
/// * `sign_func` must remain valid for the lifetime of the SSL context.
#[allow(unsafe_code)]
pub unsafe fn configure_ssl_context(
    sign_func: SignCallback,
    cert: *const c_char,
    ctx: *mut c_void,
) -> Result<(), HardmtlsError> {
    // Validate inputs.
    if cert.is_null() {
        return Err(HardmtlsError::SslError("cert pointer is null".into()));
    }
    if ctx.is_null() {
        return Err(HardmtlsError::SslError("SSL_CTX pointer is null".into()));
    }

    // SAFETY: cert is guaranteed non-null and null-terminated by the caller.
    let cert_cstr = unsafe { CStr::from_ptr(cert) };
    let cert_pem = cert_cstr
        .to_str()
        .map_err(|_| HardmtlsError::SslError("cert is not valid UTF-8".into()))?;

    if cert_pem.is_empty() {
        return Err(HardmtlsError::SslError("cert PEM is empty".into()));
    }

    // Validate that the PEM can be parsed as an X509 certificate.
    let _x509 = openssl::x509::X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| HardmtlsError::SslError(format!("failed to parse cert PEM: {e}")))?;

    // TODO: Implement SSL_CTX manipulation using OpenSSL 4.0 Provider API
    // or BoringSSL's SSL_CTX_set_private_key_method.
    //
    // Steps needed:
    // 1. SSL_CTX_use_certificate(ctx, x509)
    // 2. Create custom EVP_PKEY with sign_func callback
    //    - OpenSSL 4.0: custom Provider (OSSL_DISPATCH for EVP_SIGNATURE)
    //    - BoringSSL: SSL_CTX_set_private_key_method (trivial)
    // 3. SSL_CTX_use_PrivateKey(ctx, custom_key)

    let _ = (sign_func, ctx); // Suppress unused warnings.
    let _ = ptr::null::<c_void>(); // Suppress unused import.

    Err(HardmtlsError::SslError(
        "not yet implemented — awaiting OpenSSL 4.0 Provider API design".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{c_int, c_uchar};

    /// Dummy extern "C" sign function for testing.
    #[allow(unsafe_code)]
    unsafe extern "C" fn dummy_sign(
        _sig: *mut c_uchar,
        _sig_len: *mut usize,
        _tbs: *const c_uchar,
        _tbs_len: usize,
    ) -> c_int {
        1
    }

    #[test]
    fn null_cert_returns_error() {
        #[allow(unsafe_code)]
        let result = unsafe {
            configure_ssl_context(
                dummy_sign,
                ptr::null(),
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
        #[allow(unsafe_code)]
        let result = unsafe {
            configure_ssl_context(
                dummy_sign,
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
        #[allow(unsafe_code)]
        let result = unsafe { configure_ssl_context(dummy_sign, ptr::null(), ptr::null_mut()) };
        assert!(matches!(
            result,
            Err(HardmtlsError::SslError(ref msg)) if msg == "cert pointer is null"
        ));
    }

    #[test]
    fn empty_cert_pem_returns_error() {
        let empty = std::ffi::CString::new("").unwrap();
        #[allow(unsafe_code)]
        let result = unsafe {
            configure_ssl_context(
                dummy_sign,
                empty.as_ptr(),
                ptr::null_mut::<c_void>().wrapping_add(1),
            )
        };
        assert!(matches!(
            result,
            Err(HardmtlsError::SslError(ref msg)) if msg == "cert PEM is empty"
        ));
    }

    #[test]
    fn invalid_cert_pem_returns_error() {
        let bad_pem = std::ffi::CString::new("not a valid PEM").unwrap();
        #[allow(unsafe_code)]
        let result = unsafe {
            configure_ssl_context(
                dummy_sign,
                bad_pem.as_ptr(),
                ptr::null_mut::<c_void>().wrapping_add(1),
            )
        };
        assert!(matches!(result, Err(HardmtlsError::SslError(_))));
    }
}
