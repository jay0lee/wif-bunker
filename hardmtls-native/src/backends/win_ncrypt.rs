//! Windows NCrypt/CNG backend for hardmTLS.
//!
//! This module provides the implementation of `SigningBackend` for Windows,
//! utilizing the Cryptography API: Next Generation (CNG) to interface with
//! hardware keys stored in the TPM or Windows certificate store.

use crate::backends::SigningBackend;
use crate::config::WindowsStoreConfig;
use crate::error::HardmtlsError;

/// Windows NCrypt/CNG signing backend.
pub struct NcryptBackend {
    /// The certificate store name.
    pub store: String,
    /// The cryptographic provider name.
    pub provider: String,
    /// The issuer of the certificate to use.
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
}

impl SigningBackend for NcryptBackend {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, HardmtlsError> {
        Err(HardmtlsError::NcryptError(
            "not yet implemented".to_string(),
        ))
    }

    fn certificate_pem(&self) -> Result<String, HardmtlsError> {
        Err(HardmtlsError::NcryptError(
            "not yet implemented".to_string(),
        ))
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
    fn test_sign_stub() {
        let config = WindowsStoreConfig {
            store: "MY".to_string(),
            provider: "Microsoft Platform Crypto Provider".to_string(),
            issuer: "CN=MyIssuer".to_string(),
        };
        let backend = NcryptBackend::new(&config).unwrap();
        let result = backend.sign(b"data");
        assert!(matches!(result, Err(HardmtlsError::NcryptError(_))));
    }

    #[test]
    fn test_certificate_pem_stub() {
        let config = WindowsStoreConfig {
            store: "MY".to_string(),
            provider: "Microsoft Platform Crypto Provider".to_string(),
            issuer: "CN=MyIssuer".to_string(),
        };
        let backend = NcryptBackend::new(&config).unwrap();
        let result = backend.certificate_pem();
        assert!(matches!(result, Err(HardmtlsError::NcryptError(_))));
    }
}
