//! OpenSSL `SSL_CTX` configuration for hardware-backed mTLS.
//!
//! This module manipulates raw OpenSSL `SSL_CTX*` pointers received from
//! Python's `ssl` module. It uses the hardmTLS OpenSSL Provider (see
//! [`crate::provider`]) to create custom `EVP_PKEY` objects that delegate
//! signing to the callback provided by google-auth.
//!
//! # Flow
//!
//! 1. Register the hardmTLS provider (once)
//! 2. Parse the PEM certificate
//! 3. Load the certificate into the `SSL_CTX`
//! 4. Create a custom `EVP_PKEY` backed by our provider
//! 5. Attach the custom key to the `SSL_CTX`
//!
//! When OpenSSL performs a TLS handshake, it routes signing through our
//! provider, which calls the `sign_func` callback.

use std::ffi::{c_char, c_void, CStr};

use foreign_types_shared::ForeignType;

use crate::error::HardmtlsError;
use crate::SignCallback;

/// Configure an OpenSSL `SSL_CTX` with a client certificate and custom signing key.
///
/// This function:
/// 1. Registers the hardmTLS OpenSSL Provider (idempotent)
/// 2. Parses the PEM-encoded certificate
/// 3. Loads the certificate into the `SSL_CTX`
/// 4. Creates a custom `EVP_PKEY` via the provider that delegates signing to `sign_func`
/// 5. Attaches the custom key to the `SSL_CTX`
///
/// # Safety
///
/// * `cert` must be a valid null-terminated C string containing PEM data.
/// * `ctx` must be a valid OpenSSL `SSL_CTX*` pointer from Python's `ssl` module.
/// * `sign_func` must remain valid for the lifetime of the SSL context.
///
/// # Errors
///
/// Returns [`HardmtlsError::SslError`] if any step fails (null pointers,
/// invalid PEM, provider registration failure, etc.).
#[allow(unsafe_code)]
pub unsafe fn configure_ssl_context(
    sign_func: SignCallback,
    cert: *const c_char,
    ctx: *mut c_void,
) -> Result<(), HardmtlsError> {
    // ── Input validation ───────────────────────────────────────────────
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

    // ── Parse certificate ──────────────────────────────────────────────
    let x509 = openssl::x509::X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| HardmtlsError::SslError(format!("failed to parse cert PEM: {e}")))?;

    // ── Register our provider ──────────────────────────────────────────
    crate::provider::register_provider()?;

    // ── Load certificate into SSL_CTX ──────────────────────────────────
    let ssl_ctx = ctx.cast::<openssl_sys::SSL_CTX>();

    // SAFETY: ssl_ctx is valid (guaranteed by caller), x509 is valid.
    let rc = unsafe { openssl_sys::SSL_CTX_use_certificate(ssl_ctx, x509.as_ptr()) };
    if rc != 1 {
        return Err(HardmtlsError::SslError(
            "SSL_CTX_use_certificate failed".into(),
        ));
    }

    // ── Create custom EVP_PKEY via our provider ────────────────────────
    // TODO: Complete the EVP_PKEY creation flow:
    // 1. EVP_PKEY_CTX_new_from_name(NULL, "hardmtls-key", "provider=hardmtls")
    // 2. EVP_PKEY_fromdata_init(pkey_ctx)
    // 3. Build OSSL_PARAM array with sign_func pointer
    // 4. EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_KEYPAIR, params)
    // 5. SSL_CTX_use_PrivateKey(ssl_ctx, pkey)
    //
    // This requires completing the keymgmt_import implementation in provider.rs
    // to accept and store the sign_func pointer via OSSL_PARAM.

    let _ = sign_func; // Suppress unused warning until EVP_PKEY flow is complete.

    log::info!("hardmTLS: SSL_CTX configured with certificate (custom key pending)");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{c_int, c_uchar};
    use std::ptr;

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
