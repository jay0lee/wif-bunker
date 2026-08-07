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

use std::ffi::{c_char, c_int, c_void, CStr};

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
    log::debug!("hardmTLS: cert PEM parsed OK ({} bytes)", cert_pem.len());

    // ── Register our provider ──────────────────────────────────────────
    crate::provider::register_provider()?;
    log::debug!("hardmTLS: provider registered");

    // ── Load certificate into SSL_CTX ──────────────────────────────────
    let ssl_ctx = ctx.cast::<openssl_sys::SSL_CTX>();
    log::debug!(
        "hardmTLS: calling SSL_CTX_use_certificate (ssl_ctx={:?})",
        ssl_ctx
    );

    // SAFETY: ssl_ctx is valid (guaranteed by caller), x509 is valid.
    let rc = unsafe { openssl_sys::SSL_CTX_use_certificate(ssl_ctx, x509.as_ptr()) };
    if rc != 1 {
        return Err(HardmtlsError::SslError(
            "SSL_CTX_use_certificate failed".into(),
        ));
    }
    log::debug!("hardmTLS: SSL_CTX_use_certificate OK");

    // ── Detect the cert's public key type and compute metadata ─────────
    let pub_key = x509
        .public_key()
        .map_err(|e| HardmtlsError::SslError(format!("failed to get public key: {e}")))?;

    let (key_type_name, key_bits, security_bits, max_sig_size, group_name) =
        if let Ok(rsa) = pub_key.rsa() {
            let bits = rsa.size() as c_int * 8; // RSA::size() returns bytes
            let sec_bits = rsa_security_bits(bits);
            let max_size = rsa.size() as c_int; // signature = modulus size in bytes
            (c"RSA", bits, sec_bits, max_size, None)
        } else if let Ok(ec) = pub_key.ec_key() {
            let nid = ec
                .group()
                .curve_name()
                .ok_or_else(|| HardmtlsError::SslError("EC key has no named curve".into()))?;
            let (bits, sec_bits, max_size) = ec_key_metadata(nid)?;
            // Get the curve's short name (e.g., "prime256v1").
            let curve_name = nid.short_name().map(|s| s.to_string()).ok();
            (c"EC", bits, sec_bits, max_size, curve_name)
        } else {
            return Err(HardmtlsError::SslError(
                "unsupported key type in certificate".into(),
            ));
        };

    log::info!(
        "hardmTLS: key metadata: type={}, bits={}, security_bits={}, max_sig_size={}, group={:?}",
        key_type_name.to_str().unwrap_or("?"),
        key_bits,
        security_bits,
        max_sig_size,
        group_name.as_deref().unwrap_or("(none)")
    );

    // ── Create custom EVP_PKEY via our provider ────────────────────────
    log::debug!("hardmTLS: creating provider EVP_PKEY");
    let pkey = unsafe {
        create_provider_pkey(
            sign_func,
            key_type_name,
            key_bits,
            security_bits,
            max_sig_size,
            group_name.as_deref(),
        )
    }?;
    log::debug!("hardmTLS: provider EVP_PKEY created ({:?})", pkey);

    // SAFETY: ssl_ctx and pkey are valid.
    log::debug!("hardmTLS: calling SSL_CTX_use_PrivateKey");
    let rc = unsafe { openssl_sys::SSL_CTX_use_PrivateKey(ssl_ctx, pkey) };

    extern "C" {
        fn SSL_CTX_set_client_cert_cb(
            ctx: *mut openssl_sys::SSL_CTX,
            cb: Option<
                unsafe extern "C" fn(
                    ssl: *mut openssl_sys::SSL,
                    x509: *mut *mut openssl_sys::X509,
                    pkey: *mut *mut openssl_sys::EVP_PKEY,
                ) -> c_int,
            >,
        );
    }
    unsafe {
        SSL_CTX_set_client_cert_cb(ssl_ctx, Some(client_cert_cb));
    }

    // Free the EVP_PKEY (SSL_CTX_use_PrivateKey increments the refcount).
    // SAFETY: pkey is valid.
    unsafe { openssl_sys::EVP_PKEY_free(pkey) };

    if rc != 1 {
        return Err(HardmtlsError::SslError(
            "SSL_CTX_use_PrivateKey failed".into(),
        ));
    }

    // ── Enable TLS 1.3 post-handshake authentication ───────────────────
    // In TLS 1.3, client certificates are not sent during the initial
    // handshake. Instead, the server sends a CertificateRequest *after*
    // the handshake via post-handshake authentication (PHA). Without
    // enabling PHA, the client never advertises support, the server
    // never requests the cert, and mTLS fails silently.
    unsafe { openssl_sys::SSL_CTX_set_post_handshake_auth(ssl_ctx, 1) };
    log::debug!("hardmTLS: TLS 1.3 post-handshake auth enabled");

    log::info!("hardmTLS: SSL_CTX configured with certificate and custom key");

    Ok(())
}

/// Compute security bits for an RSA key based on NIST SP800-57 Table 2.
fn rsa_security_bits(key_bits: c_int) -> c_int {
    match key_bits {
        n if n >= 15360 => 256,
        n if n >= 7680 => 192,
        n if n >= 3072 => 128,
        n if n >= 2048 => 112,
        n if n >= 1024 => 80,
        _ => 0,
    }
}

/// Get key metadata (bits, security_bits, max_sig_size) for an EC key by curve NID.
fn ec_key_metadata(nid: openssl::nid::Nid) -> Result<(c_int, c_int, c_int), HardmtlsError> {
    use openssl::nid::Nid;

    // max_sig_size for ECDSA = 2 * (key_bytes + 1) + 6 (DER overhead)
    // This is a conservative upper bound matching OpenSSL's internal calculation.
    match nid {
        Nid::X9_62_PRIME256V1 => Ok((256, 128, 72)), // P-256
        Nid::SECP384R1 => Ok((384, 192, 104)),       // P-384
        Nid::SECP521R1 => Ok((521, 256, 141)),       // P-521
        _ => Err(HardmtlsError::SslError(format!(
            "unsupported EC curve NID: {:?}",
            nid
        ))),
    }
}

/// Create an `EVP_PKEY` backed by our hardmTLS provider.
///
/// The key stores `sign_func` as its internal signing callback, along with
/// key metadata that OpenSSL queries via `EVP_PKEY_get_size()` etc.
///
/// # Safety
///
/// `sign_func` must remain valid for the lifetime of the returned `EVP_PKEY`.
#[allow(unsafe_code)]
unsafe fn create_provider_pkey(
    sign_func: SignCallback,
    key_type: &std::ffi::CStr,
    key_bits: c_int,
    security_bits: c_int,
    max_sig_size: c_int,
    group_name: Option<&str>,
) -> Result<*mut openssl_sys::EVP_PKEY, HardmtlsError> {
    use crate::provider_ffi::{
        HARDMTLS_PARAM_GROUP_NAME, HARDMTLS_PARAM_KEY_BITS, HARDMTLS_PARAM_MAX_SIZE,
        HARDMTLS_PARAM_SECURITY_BITS, HARDMTLS_PARAM_SIGN_FUNC, OSSL_PARAM_INTEGER,
        OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING,
    };

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

    // Step 3: Build OSSL_PARAM array with sign_func + key metadata.
    let mut sign_func_bytes = sign_func;
    let mut key_bits_val = key_bits;
    let mut security_bits_val = security_bits;
    let mut max_sig_size_val = max_sig_size;

    // Prepare group name as a null-terminated CString (kept alive on stack).
    let group_cstring = group_name.map(|s| std::ffi::CString::new(s).unwrap());

    // Build params — use a Vec so we can conditionally include group name.
    let mut params_vec: Vec<openssl_sys::OSSL_PARAM> = vec![
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_SIGN_FUNC.as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data: std::ptr::addr_of_mut!(sign_func_bytes).cast::<std::ffi::c_void>(),
            data_size: std::mem::size_of::<SignCallback>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_KEY_BITS.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: std::ptr::addr_of_mut!(key_bits_val).cast::<std::ffi::c_void>(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_SECURITY_BITS.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: std::ptr::addr_of_mut!(security_bits_val).cast::<std::ffi::c_void>(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_MAX_SIZE.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: std::ptr::addr_of_mut!(max_sig_size_val).cast::<std::ffi::c_void>(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
    ];

    // Conditionally add group name for EC keys.
    if let Some(ref cstr) = group_cstring {
        params_vec.push(openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_GROUP_NAME.as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            // SAFETY: cstr is alive and immutable on the stack; cast away
            // const via cast_mut because OSSL_PARAM.data is *mut c_void
            // but OpenSSL only reads from it during fromdata.
            data: cstr.as_ptr().cast_mut().cast::<std::ffi::c_void>(),
            data_size: cstr.to_bytes().len(),
            return_size: 0,
        });
    }

    // Sentinel.
    params_vec.push(openssl_sys::OSSL_PARAM {
        key: std::ptr::null(),
        data_type: 0,
        data: std::ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    });

    // Step 4: Create the EVP_PKEY.
    let mut pkey: *mut openssl_sys::EVP_PKEY = std::ptr::null_mut();
    let rc = unsafe {
        openssl_sys::EVP_PKEY_fromdata(
            pkey_ctx,
            std::ptr::addr_of_mut!(pkey),
            openssl_sys::EVP_PKEY_KEYPAIR,
            // SAFETY: params array is valid and null-terminated.
            params_vec.as_ptr().cast_mut(),
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
        let result =
            unsafe { super::create_provider_pkey(dummy_sign, c"RSA", 2048, 112, 256, None) };

        assert!(result.is_ok(), "create_provider_pkey failed: {result:?}");

        // Clean up the key.
        #[allow(unsafe_code)]
        if let Ok(pkey) = result {
            unsafe { openssl_sys::EVP_PKEY_free(pkey) };
        }
    }
}

#[allow(unsafe_code)]
extern "C" fn client_cert_cb(
    ssl: *mut openssl_sys::SSL,
    x509: *mut *mut openssl_sys::X509,
    pkey: *mut *mut openssl_sys::EVP_PKEY,
) -> std::ffi::c_int {
    unsafe {
        let ssl_ctx = openssl_sys::SSL_get_SSL_CTX(ssl);
        if ssl_ctx.is_null() {
            return 0;
        }

        let cert = openssl_sys::SSL_CTX_get0_certificate(ssl_ctx);
        let private_key = openssl_sys::SSL_CTX_get0_privatekey(ssl_ctx);

        if cert.is_null() || private_key.is_null() {
            return 0;
        }

        openssl_sys::X509_up_ref(cert);
        openssl_sys::EVP_PKEY_up_ref(private_key);

        *x509 = cert;
        *pkey = private_key;

        log::debug!("hardmTLS: client_cert_cb invoked, forcing client cert selection");
        1
    }
}
