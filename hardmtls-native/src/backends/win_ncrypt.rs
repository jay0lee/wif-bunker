//! Windows NCrypt/CNG backend for hardmTLS.
//!
//! This module provides the implementation of `SigningBackend` for Windows,
//! utilizing the Cryptography API: Next Generation (CNG) to interface with
//! hardware keys stored in the TPM or Windows certificate store.
//!
//! ## Certificate Lookup
//!
//! The backend opens the Windows Certificate Store (e.g., `MY` for the
//! Current User) and enumerates certificates. It matches certificates
//! whose **issuer** string contains the configured issuer value.
//!
//! ## Signing
//!
//! `google-auth` pre-hashes with SHA-256 before calling `SignForPython`,
//! so our `sign()` method receives a 32-byte SHA-256 digest. For EC keys
//! we pass the digest directly to `NCryptSignHash`; for RSA keys we use
//! `BCRYPT_PAD_PKCS1` with SHA-256 padding info.
//!
//! ## Safety
//!
//! This module requires `unsafe` for Windows CNG FFI calls. The parent
//! `mod.rs` applies `#[allow(unsafe_code)]` to this module.

use crate::backends::SigningBackend;
use crate::config::WindowsStoreConfig;
use crate::error::HardmtlsError;

use std::ptr;
use std::slice;

use windows_sys::Win32::Foundation::TRUE;
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertGetNameStringW,
    CertOpenStore, CryptAcquireCertificatePrivateKey, NCryptFreeObject, NCryptGetProperty,
    NCryptSignHash, BCRYPT_PAD_PKCS1, BCRYPT_PKCS1_PADDING_INFO, CERT_CONTEXT,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
    CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NCRYPT_KEY_HANDLE,
};

/// Wide (UTF-16) null-terminated string for `NCRYPT_ALGORITHM_GROUP_PROPERTY`.
///
/// Corresponds to the Windows constant `NCRYPT_ALGORITHM_GROUP_PROPERTY`
/// (`L"Algorithm Group"`).
const NCRYPT_ALGORITHM_GROUP_PROPERTY_W: &[u16] = &[
    b'A' as u16,
    b'l' as u16,
    b'g' as u16,
    b'o' as u16,
    b'r' as u16,
    b'i' as u16,
    b't' as u16,
    b'h' as u16,
    b'm' as u16,
    b' ' as u16,
    b'G' as u16,
    b'r' as u16,
    b'o' as u16,
    b'u' as u16,
    b'p' as u16,
    0,
];

/// Wide (UTF-16) null-terminated string `"ECDSA"`.
const ECDSA_GROUP: &[u16] = &[
    b'E' as u16,
    b'C' as u16,
    b'D' as u16,
    b'S' as u16,
    b'A' as u16,
    0,
];

/// Wide (UTF-16) null-terminated string `"ECDH"`.
const ECDH_GROUP: &[u16] = &[b'E' as u16, b'C' as u16, b'D' as u16, b'H' as u16, 0];

/// Wide (UTF-16) null-terminated string `"RSA"`.
const RSA_GROUP: &[u16] = &[b'R' as u16, b'S' as u16, b'A' as u16, 0];

/// Wide (UTF-16) null-terminated string for SHA-256 algorithm identifier.
///
/// Corresponds to the Windows constant `BCRYPT_SHA256_ALGORITHM`
/// (`L"SHA256"`).
const BCRYPT_SHA256_ALGORITHM_W: &[u16] = &[
    b'S' as u16,
    b'H' as u16,
    b'A' as u16,
    b'2' as u16,
    b'5' as u16,
    b'6' as u16,
    0,
];

/// Key algorithm group detected from NCrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAlgorithm {
    /// Elliptic Curve (ECDSA/ECDH).
    Ec,
    /// RSA.
    Rsa,
}

/// Windows NCrypt/CNG signing backend.
pub struct NcryptBackend {
    /// The certificate store name (e.g., `"MY"`).
    pub store: String,
    /// The store location: `"current_user"` or `"local_machine"`.
    pub provider: String,
    /// The issuer substring to match certificates against.
    pub issuer: String,
}

impl NcryptBackend {
    /// Creates a new `NcryptBackend` from the given configuration.
    ///
    /// # Errors
    ///
    /// Returns `HardmtlsError::NcryptError` if the issuer is empty.
    pub fn new(config: &WindowsStoreConfig) -> Result<Self, HardmtlsError> {
        if config.issuer.is_empty() {
            return Err(HardmtlsError::NcryptError(
                "issuer cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            store: config.store.clone(),
            provider: config.provider.clone(),
            issuer: config.issuer.clone(),
        })
    }

    /// Returns the store flags for `CertOpenStore` based on `self.provider`.
    fn store_flags(&self) -> u32 {
        if self.provider.eq_ignore_ascii_case("local_machine") {
            CERT_SYSTEM_STORE_LOCAL_MACHINE
        } else {
            // Default to current user.
            CERT_SYSTEM_STORE_CURRENT_USER
        }
    }

    /// Open the Windows Certificate Store and find the certificate whose
    /// issuer matches `self.issuer`. Calls `f` with the cert context,
    /// then cleans up the cert context and store handle.
    fn with_matching_cert<F, R>(&self, f: F) -> Result<R, HardmtlsError>
    where
        F: FnOnce(*const CERT_CONTEXT) -> Result<R, HardmtlsError>,
    {
        // Encode the store name as a null-terminated UTF-16 string.
        let store_name: Vec<u16> = self
            .store
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let h_store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                self.store_flags(),
                store_name.as_ptr().cast(),
            )
        };

        if h_store.is_null() {
            return Err(HardmtlsError::NcryptError(format!(
                "CertOpenStore failed for store '{}' (provider={})",
                self.store, self.provider,
            )));
        }

        let result = self.find_and_use_cert(h_store, f);

        // Always close the store.
        unsafe {
            CertCloseStore(h_store, 0);
        }

        result
    }

    /// Enumerate certificates in the open store, find the matching one,
    /// call `f`, and clean up the cert context.
    fn find_and_use_cert<F, R>(
        &self,
        h_store: *mut std::ffi::c_void,
        f: F,
    ) -> Result<R, HardmtlsError>
    where
        F: FnOnce(*const CERT_CONTEXT) -> Result<R, HardmtlsError>,
    {
        let mut cert_ctx: *const CERT_CONTEXT = ptr::null();

        loop {
            cert_ctx = unsafe { CertEnumCertificatesInStore(h_store, cert_ctx) };

            if cert_ctx.is_null() {
                break;
            }

            if self.cert_issuer_matches(cert_ctx) {
                // Found a match — call the user function, then free the
                // cert context and return.
                let result = f(cert_ctx);
                unsafe {
                    CertFreeCertificateContext(cert_ctx);
                }
                return result;
            }
            // CertEnumCertificatesInStore automatically frees the
            // previous context when called with a non-null prev pointer,
            // so no explicit free is needed in the loop body.
        }

        Err(HardmtlsError::NcryptError(format!(
            "no certificate found with issuer matching '{}'",
            self.issuer,
        )))
    }

    /// Check if the issuer of the certificate at `cert_ctx` contains
    /// `self.issuer` as a substring.
    fn cert_issuer_matches(&self, cert_ctx: *const CERT_CONTEXT) -> bool {
        let mut name_buf = [0u16; 256];

        // Get the issuer name as a simple display string.
        // dwFlags=1 is CERT_NAME_ISSUER_FLAG.
        let len = unsafe {
            CertGetNameStringW(
                cert_ctx,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                1, // CERT_NAME_ISSUER_FLAG
                ptr::null(),
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
            )
        };

        if len <= 1 {
            // Empty or error — len includes null terminator, so 1 = empty.
            return false;
        }

        // Convert to Rust string (len includes null terminator).
        let issuer_str = String::from_utf16_lossy(&name_buf[..(len as usize - 1)]);
        issuer_str.contains(&self.issuer)
    }

    /// Acquire the NCrypt private key handle from a certificate context.
    ///
    /// Returns the key handle and whether the caller must free it.
    fn acquire_ncrypt_key(
        cert_ctx: *const CERT_CONTEXT,
    ) -> Result<(NCRYPT_KEY_HANDLE, bool), HardmtlsError> {
        let mut key_handle: NCRYPT_KEY_HANDLE = 0;
        let mut _key_spec: u32 = 0;
        let mut caller_free: i32 = 0;

        let success = unsafe {
            CryptAcquireCertificatePrivateKey(
                cert_ctx,
                CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                ptr::null(),
                &mut key_handle,
                &mut _key_spec,
                &mut caller_free as *mut i32 as *mut _,
            )
        };

        if success != TRUE {
            return Err(HardmtlsError::NcryptError(
                "CryptAcquireCertificatePrivateKey failed — \
                 no NCrypt key associated with certificate"
                    .to_string(),
            ));
        }

        if key_handle == 0 {
            return Err(HardmtlsError::NcryptError(
                "CryptAcquireCertificatePrivateKey returned null key handle".to_string(),
            ));
        }

        Ok((key_handle, caller_free != 0))
    }

    /// Detect the key algorithm group (EC or RSA) from an NCrypt key handle.
    fn detect_key_algorithm(key_handle: NCRYPT_KEY_HANDLE) -> Result<KeyAlgorithm, HardmtlsError> {
        let mut prop_buf = [0u16; 64];
        let mut result_len: u32 = 0;

        let status = unsafe {
            NCryptGetProperty(
                key_handle,
                NCRYPT_ALGORITHM_GROUP_PROPERTY_W.as_ptr(),
                prop_buf.as_mut_ptr().cast(),
                (prop_buf.len() * 2) as u32,
                &mut result_len,
                0,
            )
        };

        if status != 0 {
            return Err(HardmtlsError::NcryptError(format!(
                "NCryptGetProperty(AlgorithmGroup) failed: NTSTATUS 0x{status:08X}",
            )));
        }

        // result_len is in bytes; each u16 is 2 bytes.
        let char_count = (result_len as usize) / 2;
        let algo_group = &prop_buf[..char_count];

        // Compare (case-insensitive) against known groups.
        if wide_eq_ignore_case(algo_group, ECDSA_GROUP)
            || wide_eq_ignore_case(algo_group, ECDH_GROUP)
        {
            Ok(KeyAlgorithm::Ec)
        } else if wide_eq_ignore_case(algo_group, RSA_GROUP) {
            Ok(KeyAlgorithm::Rsa)
        } else {
            let group_str = String::from_utf16_lossy(algo_group).replace('\0', "");
            Err(HardmtlsError::NcryptError(format!(
                "unsupported key algorithm group: {group_str}",
            )))
        }
    }

    /// Sign a pre-hashed SHA-256 digest using `NCryptSignHash`.
    fn ncrypt_sign(
        key_handle: NCRYPT_KEY_HANDLE,
        algorithm: KeyAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>, HardmtlsError> {
        // For RSA, we need BCRYPT_PKCS1_PADDING_INFO on the stack.
        let pkcs1_info = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM_W.as_ptr(),
        };

        let (padding_ptr, flags): (*const std::ffi::c_void, u32) = match algorithm {
            KeyAlgorithm::Ec => {
                // EC: no padding info needed.
                (ptr::null(), 0)
            }
            KeyAlgorithm::Rsa => {
                // RSA: PKCS#1 v1.5 padding with SHA-256.
                (
                    (&pkcs1_info as *const BCRYPT_PKCS1_PADDING_INFO).cast(),
                    BCRYPT_PAD_PKCS1,
                )
            }
        };

        // First call: query signature length.
        let mut sig_len: u32 = 0;
        let status = unsafe {
            NCryptSignHash(
                key_handle,
                padding_ptr.cast_mut().cast(),
                digest.as_ptr().cast_mut(),
                digest.len() as u32,
                ptr::null_mut(),
                0,
                &mut sig_len,
                flags,
            )
        };

        if status != 0 {
            return Err(HardmtlsError::NcryptError(format!(
                "NCryptSignHash (size query) failed: NTSTATUS 0x{status:08X}",
            )));
        }

        // Second call: perform the actual signing.
        let mut signature = vec![0u8; sig_len as usize];
        let status = unsafe {
            NCryptSignHash(
                key_handle,
                padding_ptr.cast_mut().cast(),
                digest.as_ptr().cast_mut(),
                digest.len() as u32,
                signature.as_mut_ptr(),
                sig_len,
                &mut sig_len,
                flags,
            )
        };

        if status != 0 {
            return Err(HardmtlsError::NcryptError(format!(
                "NCryptSignHash failed: NTSTATUS 0x{status:08X}",
            )));
        }

        signature.truncate(sig_len as usize);
        Ok(signature)
    }
}

/// Case-insensitive comparison of two null-terminated wide strings.
/// Ignores trailing null terminators.
fn wide_eq_ignore_case(a: &[u16], b: &[u16]) -> bool {
    let a_trimmed: Vec<u16> = a.iter().copied().take_while(|&c| c != 0).collect();
    let b_trimmed: Vec<u16> = b.iter().copied().take_while(|&c| c != 0).collect();

    if a_trimmed.len() != b_trimmed.len() {
        return false;
    }

    a_trimmed.iter().zip(b_trimmed.iter()).all(|(&ac, &bc)| {
        char::from(ac as u8).to_ascii_lowercase() == char::from(bc as u8).to_ascii_lowercase()
    })
}

/// Convert DER certificate bytes to PEM format.
fn der_to_pem(der: &[u8]) -> Result<String, HardmtlsError> {
    use openssl::x509::X509;

    let x509 = X509::from_der(der).map_err(|e| {
        HardmtlsError::CertificateError(format!("failed to parse DER certificate: {e}"))
    })?;
    let pem_bytes = x509.to_pem().map_err(|e| {
        HardmtlsError::CertificateError(format!("failed to convert cert to PEM: {e}"))
    })?;
    String::from_utf8(pem_bytes)
        .map_err(|e| HardmtlsError::CertificateError(format!("PEM is not valid UTF-8: {e}")))
}

impl SigningBackend for NcryptBackend {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HardmtlsError> {
        self.with_matching_cert(|cert_ctx| {
            let (key_handle, caller_free) = Self::acquire_ncrypt_key(cert_ctx)?;

            // Detect algorithm and sign.
            let result = (|| {
                let algorithm = Self::detect_key_algorithm(key_handle)?;
                log::debug!(
                    "hardmTLS NCrypt: signing {} bytes with {:?} key",
                    data.len(),
                    algorithm,
                );
                let raw_sig = Self::ncrypt_sign(key_handle, algorithm, data)?;
                
                if matches!(algorithm, KeyAlgorithm::Ec) {
                    crate::backends::raw_ecdsa_to_der(&raw_sig)
                } else {
                    Ok(raw_sig)
                }
            })();

            // Free the key handle only if the system told us to.
            if caller_free {
                unsafe {
                    NCryptFreeObject(key_handle);
                }
            }

            result
        })
    }

    fn certificate_pem(&self) -> Result<String, HardmtlsError> {
        self.with_matching_cert(|cert_ctx| {
            // Extract the DER-encoded certificate from the CERT_CONTEXT.
            let cert_ref = unsafe { &*cert_ctx };
            let der_bytes = unsafe {
                slice::from_raw_parts(cert_ref.pbCertEncoded, cert_ref.cbCertEncoded as usize)
            };

            der_to_pem(der_bytes)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config() {
        let config = WindowsStoreConfig {
            store: "MY".to_string(),
            provider: "Microsoft Platform Crypto Provider".to_string(),
            issuer: "CN=MyIssuer".to_string(),
        };
        let backend = NcryptBackend::new(&config).unwrap();
        assert_eq!(backend.store, "MY");
        assert_eq!(backend.provider, "Microsoft Platform Crypto Provider");
        assert_eq!(backend.issuer, "CN=MyIssuer");
    }

    #[test]
    fn test_empty_issuer() {
        let config = WindowsStoreConfig {
            store: "MY".to_string(),
            provider: "Microsoft Platform Crypto Provider".to_string(),
            issuer: "".to_string(),
        };
        let result = NcryptBackend::new(&config);
        assert!(matches!(result, Err(HardmtlsError::NcryptError(_))));
    }

    #[test]
    fn test_store_flags_current_user() {
        let config = WindowsStoreConfig {
            store: "MY".to_string(),
            provider: "current_user".to_string(),
            issuer: "CN=Test".to_string(),
        };
        let backend = NcryptBackend::new(&config).unwrap();
        assert_eq!(backend.store_flags(), CERT_SYSTEM_STORE_CURRENT_USER);
    }

    #[test]
    fn test_store_flags_local_machine() {
        let config = WindowsStoreConfig {
            store: "MY".to_string(),
            provider: "local_machine".to_string(),
            issuer: "CN=Test".to_string(),
        };
        let backend = NcryptBackend::new(&config).unwrap();
        assert_eq!(backend.store_flags(), CERT_SYSTEM_STORE_LOCAL_MACHINE);
    }

    #[test]
    fn test_store_flags_default() {
        // Any unrecognized provider should default to current_user.
        let config = WindowsStoreConfig {
            store: "MY".to_string(),
            provider: "some_other_value".to_string(),
            issuer: "CN=Test".to_string(),
        };
        let backend = NcryptBackend::new(&config).unwrap();
        assert_eq!(backend.store_flags(), CERT_SYSTEM_STORE_CURRENT_USER);
    }

    #[test]
    fn test_no_matching_certificate() {
        // Opens the real store but looks for a cert that won't exist.
        let config = WindowsStoreConfig {
            store: "MY".to_string(),
            provider: "current_user".to_string(),
            issuer: "CN=Definitely-Not-In-Store-12345-XYZ".to_string(),
        };
        let backend = NcryptBackend::new(&config).unwrap();
        let result = backend.certificate_pem();
        assert!(result.is_err());
        if let Err(HardmtlsError::NcryptError(msg)) = result {
            assert!(msg.contains("no certificate found"), "got: {msg}");
        } else {
            panic!("Expected NcryptError");
        }
    }

    #[test]
    fn test_sign_no_matching_certificate() {
        let config = WindowsStoreConfig {
            store: "MY".to_string(),
            provider: "current_user".to_string(),
            issuer: "CN=Definitely-Not-In-Store-12345-XYZ".to_string(),
        };
        let backend = NcryptBackend::new(&config).unwrap();
        let result = backend.sign(b"test_digest_32bytes_padding_here");
        assert!(result.is_err());
    }

    #[test]
    fn test_wide_eq_ignore_case_match() {
        assert!(wide_eq_ignore_case(
            &[
                b'E' as u16,
                b'C' as u16,
                b'D' as u16,
                b'S' as u16,
                b'A' as u16,
                0
            ],
            ECDSA_GROUP,
        ));
    }

    #[test]
    fn test_wide_eq_ignore_case_lowercase() {
        assert!(wide_eq_ignore_case(
            &[
                b'e' as u16,
                b'c' as u16,
                b'd' as u16,
                b's' as u16,
                b'a' as u16,
                0
            ],
            ECDSA_GROUP,
        ));
    }

    #[test]
    fn test_wide_eq_ignore_case_mismatch() {
        assert!(!wide_eq_ignore_case(RSA_GROUP, ECDSA_GROUP));
    }

    #[test]
    fn test_wide_eq_ignore_case_different_lengths() {
        assert!(!wide_eq_ignore_case(ECDH_GROUP, ECDSA_GROUP));
    }

    #[test]
    fn test_der_to_pem() {
        // Generate a self-signed cert for testing.
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "Test").unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        let der = builder.build().to_der().unwrap();
        let pem = der_to_pem(&der).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
    }
}
