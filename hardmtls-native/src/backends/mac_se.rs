//! macOS Security.framework backend for hardmTLS.
//!
//! This module provides the implementation of `SigningBackend` for macOS,
//! utilizing the Security.framework to interface with hardware keys stored
//! in the Secure Enclave and Keychain.

use crate::backends::SigningBackend;
use crate::config::MacosKeychainConfig;
use crate::error::HardmtlsError;

/// macOS Secure Enclave signing backend.
pub struct MacSeBackend {
    /// The issuer of the certificate to use.
    pub issuer: String,
}

impl MacSeBackend {
    /// Creates a new `MacSeBackend` from the given configuration.
    ///
    /// # Errors
    ///
    /// Returns `HardmtlsError::SecurityFrameworkError` if the issuer is empty.
    pub fn new(config: &MacosKeychainConfig) -> Result<Self, HardmtlsError> {
        if config.issuer.is_empty() {
            return Err(HardmtlsError::SecurityFrameworkError(
                "issuer cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            issuer: config.issuer.clone(),
        })
    }
}

impl SigningBackend for MacSeBackend {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, HardmtlsError> {
        Err(HardmtlsError::SecurityFrameworkError(
            "not yet implemented".to_string(),
        ))
    }

    fn certificate_pem(&self) -> Result<String, HardmtlsError> {
        Err(HardmtlsError::SecurityFrameworkError(
            "not yet implemented".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config() {
        let config = MacosKeychainConfig {
            issuer: "CN=MyIssuer".to_string(),
        };
        let backend = MacSeBackend::new(&config).unwrap();
        assert_eq!(backend.issuer, "CN=MyIssuer");
    }

    #[test]
    fn test_empty_issuer() {
        let config = MacosKeychainConfig {
            issuer: String::new(),
        };
        let result = MacSeBackend::new(&config);
        assert!(matches!(
            result,
            Err(HardmtlsError::SecurityFrameworkError(_))
        ));
    }

    #[test]
    fn test_sign_stub() {
        let config = MacosKeychainConfig {
            issuer: "CN=MyIssuer".to_string(),
        };
        let backend = MacSeBackend::new(&config).unwrap();
        let result = backend.sign(b"data");
        assert!(matches!(
            result,
            Err(HardmtlsError::SecurityFrameworkError(_))
        ));
    }

    #[test]
    fn test_certificate_pem_stub() {
        let config = MacosKeychainConfig {
            issuer: "CN=MyIssuer".to_string(),
        };
        let backend = MacSeBackend::new(&config).unwrap();
        let result = backend.certificate_pem();
        assert!(matches!(
            result,
            Err(HardmtlsError::SecurityFrameworkError(_))
        ));
    }
}
