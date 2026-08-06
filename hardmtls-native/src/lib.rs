//! hardmTLS — Hardware-backed mTLS signing library.
//!
//! A drop-in replacement for Google's ECP (Enterprise Certificate Proxy).
//! Exports the same C API that `google-auth`'s `_custom_tls_signer.py` expects,
//! so downstream apps (`gcloud`, `terraform`, any Google SDK) load it transparently.
//!
//! # Architecture
//!
//! One shared library, three signing backends:
//! - [`backends::pkcs11`] — PKCS#11 (Linux TPM, `YubiKey` on all platforms)
//! - `backends::win_ncrypt` — Windows `NCrypt`/CNG (Windows TPM)
//! - `backends::mac_se` — macOS `Security.framework` (Secure Enclave + Keychain)
//!
//! # Design Note
//!
//! This crate is designed to be detachable from wif-bunker in the future.
//! It has no dependencies on wif-bunker internals. If we decide to spin it
//! out into a standalone library, the separation should be straightforward.

// Project-wide lint configuration.
// `unsafe_code` and `missing_docs` are enforced at the Cargo.toml `[lints]` level.
// Clippy pedantic is also configured there.

pub mod backends;
pub mod config;
pub mod dispatch;
pub mod error;
pub mod provider;
pub mod provider_ffi;
pub mod ssl_ctx;

use std::ffi::{c_char, c_int, c_uchar, c_void};
use std::slice;
use std::sync::OnceLock;

use config::CertificateConfig;
use dispatch::select_backend;
use error::HardmtlsError;

/// Type alias for the signing callback that google-auth provides.
///
/// Signature: `int sign_func(uint8_t *sig, size_t *sig_len, const uint8_t *tbs, size_t tbs_len)`
///
/// The callback computes the signature over `tbs` (to-be-signed) bytes and writes
/// the result into `sig`/`sig_len`. Returns 1 on success, 0 on failure.
pub type SignCallback = unsafe extern "C" fn(
    sig: *mut c_uchar,
    sig_len: *mut usize,
    tbs: *const c_uchar,
    tbs_len: usize,
) -> c_int;

/// Global config cache to avoid re-parsing on every call.
static CONFIG_CACHE: OnceLock<CertificateConfig> = OnceLock::new();

/// Configure an OpenSSL `SSL_CTX` for hardware-backed mTLS.
///
/// This is the primary entry point called by google-auth's `_custom_tls_signer.py`.
/// It attaches the client certificate and a custom signing key (backed by hardware)
/// to the provided `SSL_CTX`.
///
/// # Arguments
///
/// * `sign_func` — Signing callback provided by google-auth (wraps `SignForPython`).
/// * `cert` — PEM-encoded client certificate (null-terminated C string).
/// * `ctx` — Raw OpenSSL `SSL_CTX*` pointer from Python's `ssl` module.
///
/// # Returns
///
/// `1` on success, `0` on failure.
///
/// # Safety
///
/// * `cert` must be a valid null-terminated C string.
/// * `ctx` must be a valid OpenSSL `SSL_CTX*` pointer.
/// * `sign_func` must be a valid function pointer matching the expected signature.
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "C" fn ConfigureSslContext(
    sign_func: SignCallback,
    cert: *const c_char,
    ctx: *mut c_void,
) -> c_int {
    let result = std::panic::catch_unwind(|| ssl_ctx::configure_ssl_context(sign_func, cert, ctx));
    match result {
        Ok(Ok(())) => 1,
        Ok(Err(e)) => {
            log::error!("hardmTLS: ConfigureSslContext failed: {e}");
            0
        }
        Err(_) => {
            log::error!("hardmTLS: ConfigureSslContext panicked");
            0
        }
    }
}

/// Retrieve the client certificate PEM from the platform keystore.
///
/// Called by google-auth's `_custom_tls_signer.py` (via the `libecp` interface).
///
/// # Protocol
///
/// 1. First call with `cert_holder = NULL` → returns the required buffer size.
/// 2. Second call with a buffer of that size → fills `cert_holder` with PEM bytes.
///
/// # Safety
///
/// * `config_path` must be a valid null-terminated C string.
/// * If `cert_holder` is non-null, it must point to a buffer of at least
///   `cert_holder_len` bytes.
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "C" fn GetCertPemForPython(
    config_path: *const c_char,
    cert_holder: *mut c_char,
    cert_holder_len: c_int,
) -> c_int {
    let result =
        std::panic::catch_unwind(|| get_cert_pem_impl(config_path, cert_holder, cert_holder_len));
    match result {
        Ok(Ok(len)) => len,
        Ok(Err(e)) => {
            log::error!("hardmTLS: GetCertPemForPython failed: {e}");
            -1
        }
        Err(_) => {
            log::error!("hardmTLS: GetCertPemForPython panicked");
            -1
        }
    }
}

/// Sign data using the hardware-backed private key.
///
/// Called by google-auth's `_custom_tls_signer.py` (via the `libecp` interface).
///
/// # Safety
///
/// * `config_path` must be a valid null-terminated C string.
/// * `input` must point to `input_len` bytes.
/// * `output` must point to a buffer of at least `output_len` bytes.
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "C" fn SignForPython(
    config_path: *const c_char,
    input: *const c_uchar,
    input_len: c_int,
    output: *mut c_uchar,
    output_len: c_int,
) -> c_int {
    let result = std::panic::catch_unwind(|| {
        sign_for_python_impl(config_path, input, input_len, output, output_len)
    });
    match result {
        Ok(Ok(len)) => len,
        Ok(Err(e)) => {
            log::error!("hardmTLS: SignForPython failed: {e}");
            -1
        }
        Err(_) => {
            log::error!("hardmTLS: SignForPython panicked");
            -1
        }
    }
}

// ── Internal implementations ───────────────────────────────────────────

/// Internal implementation of `GetCertPemForPython`.
#[allow(unsafe_code)]
unsafe fn get_cert_pem_impl(
    config_path: *const c_char,
    cert_holder: *mut c_char,
    cert_holder_len: c_int,
) -> Result<c_int, HardmtlsError> {
    let config = load_config(config_path)?;
    let backend = select_backend(&config)?;
    let cert_pem = backend.certificate_pem()?;
    let cert_bytes = cert_pem.as_bytes();

    if cert_holder.is_null() {
        // First call: return required buffer size.
        return Ok(c_int::try_from(cert_bytes.len()).unwrap_or(c_int::MAX));
    }

    let buf_len = usize::try_from(cert_holder_len).unwrap_or(0);
    let copy_len = cert_bytes.len().min(buf_len);
    // SAFETY: cert_holder is non-null and points to at least cert_holder_len bytes
    // (guaranteed by caller contract).
    unsafe {
        std::ptr::copy_nonoverlapping(cert_bytes.as_ptr(), cert_holder.cast::<u8>(), copy_len);
    }
    Ok(c_int::try_from(copy_len).unwrap_or(c_int::MAX))
}

/// Internal implementation of `SignForPython`.
#[allow(unsafe_code)]
unsafe fn sign_for_python_impl(
    config_path: *const c_char,
    input: *const c_uchar,
    input_len: c_int,
    output: *mut c_uchar,
    output_len: c_int,
) -> Result<c_int, HardmtlsError> {
    let config = load_config(config_path)?;
    let backend = select_backend(&config)?;

    let in_len = usize::try_from(input_len).unwrap_or(0);
    // SAFETY: input is guaranteed by caller to point to input_len bytes.
    let tbs = unsafe { slice::from_raw_parts(input, in_len) };

    let signature = backend.sign(tbs)?;

    let out_len = usize::try_from(output_len).unwrap_or(0);
    if signature.len() > out_len {
        return Err(HardmtlsError::BufferTooSmall {
            needed: signature.len(),
            provided: out_len,
        });
    }

    // SAFETY: output is guaranteed by caller to point to output_len bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(signature.as_ptr(), output, signature.len());
    }
    Ok(c_int::try_from(signature.len()).unwrap_or(c_int::MAX))
}

/// Load and cache the certificate configuration from a JSON file path.
#[allow(unsafe_code)]
fn load_config(config_path: *const c_char) -> Result<CertificateConfig, HardmtlsError> {
    // SAFETY: config_path is guaranteed to be a valid null-terminated C string by caller.
    let path_str = unsafe {
        std::ffi::CStr::from_ptr(config_path)
            .to_str()
            .map_err(|_| HardmtlsError::InvalidConfigPath)?
    };

    // Try to use cached config; fall back to parsing from disk.
    if let Some(cached) = CONFIG_CACHE.get() {
        return Ok(cached.clone());
    }

    let config = config::load_from_file(path_str)?;
    let _ = CONFIG_CACHE.set(config.clone());
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn configure_ssl_context_returns_zero_on_null_cert() {
        // SAFETY: Testing with null cert pointer — should fail gracefully.
        #[allow(unsafe_code)]
        let result =
            unsafe { ConfigureSslContext(dummy_sign_func, std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(result, 0, "Should return 0 (failure) on null cert");
    }

    #[test]
    fn get_cert_pem_returns_negative_on_invalid_config() {
        let bad_path = CString::new("/nonexistent/config.json").unwrap();
        // SAFETY: Testing with a valid C string but nonexistent file.
        #[allow(unsafe_code)]
        let result = unsafe { GetCertPemForPython(bad_path.as_ptr(), std::ptr::null_mut(), 0) };
        assert!(result < 0, "Should return negative on invalid config path");
    }

    #[test]
    fn sign_for_python_returns_negative_on_invalid_config() {
        let bad_path = CString::new("/nonexistent/config.json").unwrap();
        let input = b"test data";
        let mut output = [0u8; 256];
        // SAFETY: Testing with valid buffers but nonexistent config.
        #[allow(unsafe_code)]
        let result = unsafe {
            SignForPython(
                bad_path.as_ptr(),
                input.as_ptr(),
                c_int::try_from(input.len()).unwrap(),
                output.as_mut_ptr(),
                c_int::try_from(output.len()).unwrap(),
            )
        };
        assert!(result < 0, "Should return negative on invalid config path");
    }

    /// Dummy sign function for testing `ConfigureSslContext`.
    #[allow(unsafe_code)]
    unsafe extern "C" fn dummy_sign_func(
        _sig: *mut c_uchar,
        _sig_len: *mut usize,
        _tbs: *const c_uchar,
        _tbs_len: usize,
    ) -> c_int {
        1 // Always succeed
    }
}
