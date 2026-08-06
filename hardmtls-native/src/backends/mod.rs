//! Backends module for hardware-backed TLS signing.
//!
//! Provides the `SigningBackend` trait and platform-specific implementations.

use crate::error::HardmtlsError;

/// Trait for hardware-backed signing backends.
///
/// Each backend implements signing and certificate retrieval for a specific
/// platform keystore (PKCS#11, `NCrypt`, `Security.framework`).
pub trait SigningBackend: Send + Sync {
    /// Sign the given data (to-be-signed bytes) and return the signature.
    ///
    /// # Errors
    /// Returns `HardmtlsError` if signing fails.
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, HardmtlsError>;

    /// Return the client certificate in PEM format.
    ///
    /// # Errors
    /// Returns `HardmtlsError` if the certificate cannot be retrieved.
    fn certificate_pem(&self) -> Result<String, HardmtlsError>;
}

#[cfg(target_os = "macos")]
pub mod mac_se;
pub mod pkcs11;
#[cfg(target_os = "windows")]
pub mod win_ncrypt;

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBackend;

    impl SigningBackend for MockBackend {
        fn sign(&self, _tbs: &[u8]) -> Result<Vec<u8>, HardmtlsError> {
            Ok(vec![1, 2, 3])
        }

        fn certificate_pem(&self) -> Result<String, HardmtlsError> {
            Ok("pem".to_string())
        }
    }

    #[test]
    fn test_object_safety() {
        let backend: Box<dyn SigningBackend> = Box::new(MockBackend);
        assert_eq!(backend.sign(b"test").unwrap(), vec![1, 2, 3]);
        assert_eq!(backend.certificate_pem().unwrap(), "pem");
    }
}
