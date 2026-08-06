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

    // ── Detect the cert's public key type ──────────────────────────────
    let pub_key = x509
        .public_key()
        .map_err(|e| HardmtlsError::SslError(format!("failed to get public key: {e}")))?;
    let key_type_name = if pub_key.rsa().is_ok() {
        c"RSA"
    } else if pub_key.ec_key().is_ok() {
        c"EC"
    } else {
        return Err(HardmtlsError::SslError(
            "unsupported key type in certificate".into(),
        ));
    };

    // ── Create custom EVP_PKEY via our provider ────────────────────────
    let pkey = unsafe { create_provider_pkey(sign_func, key_type_name) }?;

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
    key_type: &std::ffi::CStr,
) -> Result<*mut openssl_sys::EVP_PKEY, HardmtlsError> {
    use crate::provider_ffi::{HARDMTLS_PARAM_SIGN_FUNC, OSSL_PARAM_OCTET_STRING};

    // Step 1: Create EVP_PKEY_CTX targeting our provider's keymgmt.
    let pkey_ctx = unsafe {
        openssl_sys::EVP_PKEY_CTX_new_from_name(
            std::ptr::null_mut(),                            // default lib ctx
            key_type.as_ptr(),                               // keymgmt name (RSA or EC)
            c"provider=hardmtls,hardmtls.sign=yes".as_ptr(), // target our provider
        )
    };
    if pkey_ctx.is_null() {
        return Err(HardmtlsError::SslError(format!(
            "EVP_PKEY_CTX_new_from_name failed for {}",
            key_type.to_str().unwrap_or("unknown")
        )));
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
            "EVP_PKEY_fromdata failed for provider key".into(),
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

    /// Pre-built self-signed RSA-2048 test certificate.
    ///
    /// Using a static cert avoids calling `X509Builder::sign()` at test time,
    /// which would race with our provider registration (our "RSA" signature
    /// can shadow the default provider's RSA when tests run in parallel).
    const TEST_CERT_PEM: &str = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIDETCCAfmgAwIBAgIUFDaTqlJgmNiBlPEEvPqNKwgUxWQwDQYJKoZIhvcNAQEL\n",
        "BQAwGDEWMBQGA1UEAwwNaGFyZG10bHMtdGVzdDAeFw0yNjA4MDYyMjA3MTBaFw0y\n",
        "NzA4MDYyMjA3MTBaMBgxFjAUBgNVBAMMDWhhcmRtdGxzLXRlc3QwggEiMA0GCSqG\n",
        "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtBhNOrhRW+4h6U5rNZQLonJH7tvnveVx2\n",
        "O5OcpyrgN2oYO8HL8s3rAVpLbRBNRhvanpPOUCiDLtnRmaHrPNp8nkYY91sVWuJ0\n",
        "xiAOCalYr3ACEd/QHm68tfbJ95IhaTMCvnqua0qgkVEV7g9aGpiH10mUEyJwStQj\n",
        "1fRct+fd/gzR3y8t/qRSW3194V3aFPHohJqgSbfBr92cWejtt//AY3P7RRxVLydI\n",
        "N1x+ieM0+7hVnaOCE3awfGm9HkuEmszrtnI2TwYMydRO8XqnqYxbqXkVifsmwP0/\n",
        "ayEeyQzA0RWCpre2wKhZ7q3fVlfHT2nqMiIZIxG8bB66JhL+S7txAgMBAAGjUzBR\n",
        "MB0GA1UdDgQWBBTyljdFNus9F+d7nvjUXeCG5ruRnTAfBgNVHSMEGDAWgBTyljdF\n",
        "Nus9F+d7nvjUXeCG5ruRnTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA\n",
        "A4IBAQCsENFgTzGR7llldn1QL1ylmoWH0RlTT9UaQC96oKRm8Spm3NhqVV74z7tv\n",
        "D11eT0RBQf8UTuLpFzh/roxxP+ufMuI0ONbc+Z+VyaghVyuxDdfva9RrsbqM4xQ9\n",
        "a+mZ3DvpT8Oi7lSO0GRGkTOp126xUaiezwcsIXKV7VjSt0sFQ8M3YKAC+349ciH0\n",
        "/av838WXgjCtbINWpPe5qkYGe+MfOjYDpscmriVsEWTHP24dZH/a9weyUafVk+CR\n",
        "RdTkKtUVdksz/m/lhC5C5Nrn7HSP7eZR5D5XT2iOg0sScVilkZmpYkDIS0GtTRKH\n",
        "PFTtIEW55maMi5P5ByF1IXHil/Zk\n",
        "-----END CERTIFICATE-----\n",
    );

    /// Get the test certificate PEM as a C string.
    fn generate_test_cert_pem() -> std::ffi::CString {
        std::ffi::CString::new(TEST_CERT_PEM).unwrap()
    }

    #[test]
    fn end_to_end_configure_ssl_context() {
        // Full pipeline test:
        // 1. Create a real SSL_CTX
        // 2. Generate a self-signed RSA cert
        // 3. Call configure_ssl_context → register provider + load cert +
        //    create provider EVP_PKEY + SSL_CTX_use_PrivateKey

        // Create a real SSL_CTX.
        let method = openssl::ssl::SslMethod::tls();
        let ssl_ctx_builder = openssl::ssl::SslContext::builder(method).unwrap();
        let ssl_ctx = ssl_ctx_builder.build();

        // Generate test cert.
        let cert_pem = generate_test_cert_pem();

        // Call configure_ssl_context — this is the function Python will call.
        #[allow(unsafe_code)]
        let result = unsafe {
            configure_ssl_context(
                dummy_sign,
                cert_pem.as_ptr(),
                ssl_ctx.as_ptr().cast::<c_void>(),
            )
        };

        assert!(result.is_ok(), "configure_ssl_context failed: {result:?}");
    }

    #[test]
    fn create_provider_pkey_returns_valid_key() {
        // Ensure the provider is registered.
        crate::provider::register_provider().unwrap();

        // Create a custom EVP_PKEY.
        #[allow(unsafe_code)]
        let result = unsafe { super::create_provider_pkey(dummy_sign, c"RSA") };

        assert!(result.is_ok(), "create_provider_pkey failed: {result:?}");

        // Clean up the key.
        #[allow(unsafe_code)]
        if let Ok(pkey) = result {
            unsafe { openssl_sys::EVP_PKEY_free(pkey) };
        }
    }
}
