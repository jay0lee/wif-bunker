//! PKCS#11 Signing Backend.
//!
//! This backend uses a PKCS#11 module (e.g. `libykcs11.so`, `libtpm2_pkcs11.so`,
//! or `opensc-pkcs11.so`) to perform hardware-backed signing and certificate
//! retrieval. It is cross-platform: Linux, macOS, and Windows.

use crate::backends::SigningBackend;
use crate::config::Pkcs11Config;
use crate::error::HardmtlsError;

/// The PKCS#11 signing backend.
///
/// Handles interactions with PKCS#11 tokens for retrieving client certificates
/// and performing cryptographic signatures using the token's private key.
#[derive(Debug)]
#[allow(dead_code)] // Fields will be read when signing is implemented.
pub struct Pkcs11Backend {
    /// Path to the PKCS#11 shared library module.
    module: String,
    /// Token slot identifier.
    slot: String,
    /// Token or key label.
    label: String,
    /// User PIN for the token.
    user_pin: String,
}

impl Pkcs11Backend {
    /// Creates a new `Pkcs11Backend` from the provided configuration.
    ///
    /// # Errors
    ///
    /// Returns [`HardmtlsError::Pkcs11Error`] if the `module` path is empty.
    pub fn new(config: &Pkcs11Config) -> Result<Self, HardmtlsError> {
        if config.module.is_empty() {
            return Err(HardmtlsError::Pkcs11Error(
                "PKCS#11 module path cannot be empty".into(),
            ));
        }

        Ok(Self {
            module: config.module.clone(),
            slot: config.slot.clone(),
            label: config.label.clone(),
            user_pin: config.user_pin.clone(),
        })
    }
}

impl SigningBackend for Pkcs11Backend {
    /// Signs the given `tbs` (to-be-signed) data using the token's private key.
    ///
    /// Currently a stub that always returns `Err`.
    fn sign(&self, _tbs: &[u8]) -> Result<Vec<u8>, HardmtlsError> {
        Err(HardmtlsError::Pkcs11Error("not yet implemented".into()))
    }

    /// Retrieves the PEM-encoded certificate from the token.
    ///
    /// Currently a stub that always returns `Err`.
    fn certificate_pem(&self) -> Result<String, HardmtlsError> {
        Err(HardmtlsError::CertificateError(
            "not yet implemented".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> Pkcs11Config {
        Pkcs11Config {
            module: "/usr/lib/libykcs11.so".to_string(),
            slot: "0".to_string(),
            label: "X.509 Certificate for PIV Authentication".to_string(),
            user_pin: "123456".to_string(),
        }
    }

    #[test]
    fn new_with_valid_config() {
        let config = valid_config();
        let backend = Pkcs11Backend::new(&config).expect("Should create backend successfully");

        assert_eq!(backend.module, "/usr/lib/libykcs11.so");
        assert_eq!(backend.slot, "0");
        assert_eq!(backend.label, "X.509 Certificate for PIV Authentication");
        assert_eq!(backend.user_pin, "123456");
    }

    #[test]
    fn new_with_empty_module_path_fails() {
        let config = Pkcs11Config {
            module: String::new(),
            ..valid_config()
        };

        let result = Pkcs11Backend::new(&config);
        assert!(result.is_err(), "Should fail with empty module path");
        match result.unwrap_err() {
            HardmtlsError::Pkcs11Error(msg) => assert!(msg.contains("cannot be empty")),
            other => panic!("Expected Pkcs11Error, got {other:?}"),
        }
    }

    #[test]
    fn sign_returns_stub_error() {
        let backend = Pkcs11Backend::new(&valid_config()).unwrap();
        let result = backend.sign(b"test data");

        assert!(result.is_err());
        match result.unwrap_err() {
            HardmtlsError::Pkcs11Error(msg) => assert_eq!(msg, "not yet implemented"),
            other => panic!("Expected Pkcs11Error, got {other:?}"),
        }
    }

    #[test]
    fn certificate_pem_returns_stub_error() {
        let backend = Pkcs11Backend::new(&valid_config()).unwrap();
        let result = backend.certificate_pem();

        assert!(result.is_err());
        match result.unwrap_err() {
            HardmtlsError::CertificateError(msg) => assert_eq!(msg, "not yet implemented"),
            other => panic!("Expected CertificateError, got {other:?}"),
        }
    }
}
