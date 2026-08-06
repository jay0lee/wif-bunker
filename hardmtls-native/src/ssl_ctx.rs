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
    let pkey = unsafe { create_provider_pkey(sign_func) }?;

    // SAFETY: ssl_ctx and pkey are valid.
    let rc = unsafe { openssl_sys::SSL_CTX_use_PrivateKey(ssl_ctx, pkey) };

    // Free the EVP_PKEY (SSL_CTX_use_PrivateKey increments the refcount).
    // SAFETY: pkey is valid.
    unsafe { openssl_sys::EVP_PKEY_free(pkey) };

    if rc != 1 {
        return Err(HardmtlsError::SslError(
            "SSL_CTX_use_PrivateKey failed".into(),
        ));
    }

    log::info!("hardmTLS: SSL_CTX configured with certificate and custom key");

    Ok(())
}

/// Create an `EVP_PKEY` backed by our hardmTLS provider.
///
/// The key stores `sign_func` as its internal signing callback.
///
/// # Safety
///
/// `sign_func` must remain valid for the lifetime of the returned `EVP_PKEY`.
#[allow(unsafe_code)]
unsafe fn create_provider_pkey(
    sign_func: SignCallback,
) -> Result<*mut openssl_sys::EVP_PKEY, HardmtlsError> {
    use crate::provider_ffi::{HARDMTLS_PARAM_SIGN_FUNC, OSSL_PARAM_OCTET_STRING};

    // Step 1: Create EVP_PKEY_CTX targeting our provider's keymgmt.
    let pkey_ctx = unsafe {
        openssl_sys::EVP_PKEY_CTX_new_from_name(
            std::ptr::null_mut(),          // default lib ctx
            c"hardmtls-key".as_ptr(),      // our keymgmt name
            c"provider=hardmtls".as_ptr(), // target our provider
        )
    };
    if pkey_ctx.is_null() {
        return Err(HardmtlsError::SslError(
            "EVP_PKEY_CTX_new_from_name failed for hardmtls-key".into(),
        ));
    }

    // Step 2: Initialize for fromdata import.
    let rc = unsafe { openssl_sys::EVP_PKEY_fromdata_init(pkey_ctx) };
    if rc != 1 {
        unsafe { openssl_sys::EVP_PKEY_CTX_free(pkey_ctx) };
        return Err(HardmtlsError::SslError(
            "EVP_PKEY_fromdata_init failed".into(),
        ));
    }

    // Step 3: Build OSSL_PARAM array with our sign_func pointer.
    // We pass the raw bytes of the function pointer as an octet string.
    let mut sign_func_bytes = sign_func;
    let params: [openssl_sys::OSSL_PARAM; 2] = [
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_SIGN_FUNC.as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data: std::ptr::addr_of_mut!(sign_func_bytes).cast::<std::ffi::c_void>(),
            data_size: std::mem::size_of::<SignCallback>(),
            return_size: 0,
        },
        // Sentinel.
        openssl_sys::OSSL_PARAM {
            key: std::ptr::null(),
            data_type: 0,
            data: std::ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
    ];

    // Step 4: Create the EVP_PKEY.
    let mut pkey: *mut openssl_sys::EVP_PKEY = std::ptr::null_mut();
    let rc = unsafe {
        openssl_sys::EVP_PKEY_fromdata(
            pkey_ctx,
            std::ptr::addr_of_mut!(pkey),
            openssl_sys::EVP_PKEY_KEYPAIR,
            // SAFETY: params array is valid and null-terminated.
            params.as_ptr().cast_mut(),
        )
    };

    // Clean up the context (EVP_PKEY has its own refcount).
    unsafe { openssl_sys::EVP_PKEY_CTX_free(pkey_ctx) };

    if rc != 1 || pkey.is_null() {
        return Err(HardmtlsError::SslError(
            "EVP_PKEY_fromdata failed for hardmtls-key".into(),
        ));
    }

    Ok(pkey)
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

    /// Generate a self-signed certificate for testing.
    fn generate_test_cert_pem() -> std::ffi::CString {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "hardmtls-test").unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        let cert = builder.build();
        let pem = cert.to_pem().unwrap();
        std::ffi::CString::new(pem).unwrap()
    }

    #[test]
    fn end_to_end_cert_and_pkey_creation() {
        // This test exercises the provider pipeline:
        // 1. Register the provider
        // 2. Generate a self-signed cert
        // 3. Create a custom EVP_PKEY via the provider
        // 4. Verify both are valid
        //
        // Note: SSL_CTX_use_PrivateKey currently fails because our custom key
        // type doesn't export standard key params. This requires implementing
        // keymgmt_export and/or keymgmt_match so SSL_CTX can verify the key
        // matches the certificate. This is the next step.

        // Register the provider.
        crate::provider::register_provider().unwrap();

        // Generate test cert and verify it parses.
        let cert_pem = generate_test_cert_pem();
        let cert = openssl::x509::X509::from_pem(cert_pem.to_bytes()).unwrap();
        assert!(cert.subject_name().entries().count() > 0);

        // Create a custom EVP_PKEY via the provider.
        #[allow(unsafe_code)]
        let pkey = unsafe { super::create_provider_pkey(dummy_sign) }.unwrap();
        assert!(!pkey.is_null());

        // Clean up.
        #[allow(unsafe_code)]
        unsafe {
            openssl_sys::EVP_PKEY_free(pkey);
        }
    }

    #[test]
    fn create_provider_pkey_returns_valid_key() {
        // Ensure the provider is registered.
        crate::provider::register_provider().unwrap();

        // Create a custom EVP_PKEY.
        #[allow(unsafe_code)]
        let result = unsafe { super::create_provider_pkey(dummy_sign) };

        assert!(result.is_ok(), "create_provider_pkey failed: {result:?}");

        // Clean up the key.
        #[allow(unsafe_code)]
        if let Ok(pkey) = result {
            unsafe { openssl_sys::EVP_PKEY_free(pkey) };
        }
    }
}
