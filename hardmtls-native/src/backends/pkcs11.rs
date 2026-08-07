//! PKCS#11 Signing Backend.
//!
//! This backend uses a PKCS#11 module (e.g. `libykcs11.so`, `libtpm2_pkcs11.so`,
//! or `opensc-pkcs11.so`) to perform hardware-backed signing and certificate
//! retrieval. It is cross-platform: Linux, macOS, and Windows.

use crate::backends::SigningBackend;
use crate::config::Pkcs11Config;
use crate::error::HardmtlsError;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use openssl::x509::X509;

/// The PKCS#11 signing backend.
///
/// Handles interactions with PKCS#11 tokens for retrieving client certificates
/// and performing cryptographic signatures using the token's private key.
#[derive(Debug)]
#[allow(dead_code)] // Fields are used when signing and retrieving certificates.
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

    /// Helper to run a closure with an initialized PKCS#11 session.
    fn with_session<F, R>(&self, f: F) -> Result<R, HardmtlsError>
    where
        F: FnOnce(&Session) -> Result<R, HardmtlsError>,
    {
        let pkcs11 = Pkcs11::new(&self.module)
            .map_err(|e| HardmtlsError::Pkcs11Error(format!("Failed to load module: {e}")))?;

        // CKR_CRYPTOKI_ALREADY_INITIALIZED is non-fatal — the module was
        // already initialized by another caller in this process (e.g., Python's
        // python-pkcs11 loaded the same .so during cert generation).
        // Per PKCS#11 spec §5.4, we can safely proceed.
        match pkcs11.initialize(CInitializeArgs::OsThreads) {
            Ok(()) => {}
            Err(cryptoki::error::Error::AlreadyInitialized) => {
                log::debug!("PKCS#11 already initialized — reusing existing session");
            }
            Err(e) => {
                return Err(HardmtlsError::Pkcs11Error(format!(
                    "Failed to initialize PKCS#11: {e}"
                )));
            }
        }

        let slot_id = self.slot.parse::<u64>().map_err(|_| {
            HardmtlsError::Pkcs11Error(format!("Invalid slot number: {}", self.slot))
        })?;

        let slot = cryptoki::slot::Slot::try_from(slot_id)
            .map_err(|_| HardmtlsError::Pkcs11Error(format!("Invalid slot ID: {slot_id}")))?;

        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|e| HardmtlsError::Pkcs11Error(format!("Failed to open session: {e}")))?;

        let pin = AuthPin::new(self.user_pin.clone());
        session
            .login(UserType::User, Some(&pin))
            .map_err(|e| HardmtlsError::Pkcs11Error(format!("Failed to login: {e}")))?;

        let result = f(&session);

        // Best effort logout and close, ignore errors
        let _ = session.logout();

        result
    }
}

impl SigningBackend for Pkcs11Backend {
    /// Signs the given `tbs` (to-be-signed) data using the token's private key.
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, HardmtlsError> {
        self.with_session(|session| {
            let mut template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
            if !self.label.is_empty() {
                template.push(Attribute::Label(self.label.as_bytes().to_vec()));
            }

            let keys = session.find_objects(&template).map_err(|e| {
                HardmtlsError::Pkcs11Error(format!("Failed to find private key: {e}"))
            })?;
            let key_handle = keys
                .first()
                .ok_or_else(|| HardmtlsError::Pkcs11Error("Private key not found".into()))?;

            let attrs = session
                .get_attributes(*key_handle, &[AttributeType::KeyType])
                .map_err(|e| {
                    HardmtlsError::Pkcs11Error(format!("Failed to get key attributes: {e}"))
                })?;

            let Some(Attribute::KeyType(key_type)) = attrs.first() else {
                return Err(HardmtlsError::Pkcs11Error(
                    "Key type attribute not found".into(),
                ));
            };

            let mechanism = match *key_type {
                KeyType::EC => Mechanism::Ecdsa,
                KeyType::RSA => Mechanism::RsaPkcs,
                _ => return Err(HardmtlsError::Pkcs11Error("Unsupported key type".into())),
            };

            session
                .sign(&mechanism, *key_handle, tbs)
                .map_err(|e| HardmtlsError::Pkcs11Error(format!("Failed to sign: {e}")))
        })
    }

    /// Retrieves the PEM-encoded certificate from the token.
    fn certificate_pem(&self) -> Result<String, HardmtlsError> {
        self.with_session(|session| {
            let mut template = vec![Attribute::Class(ObjectClass::CERTIFICATE)];
            if !self.label.is_empty() {
                template.push(Attribute::Label(self.label.as_bytes().to_vec()));
            }

            let certs = session
                .find_objects(&template)
                .map_err(|e| HardmtlsError::Pkcs11Error(format!("Failed to find objects: {e}")))?;
            let cert_handle = certs
                .first()
                .ok_or_else(|| HardmtlsError::CertificateError("Certificate not found".into()))?;

            let attrs = session
                .get_attributes(*cert_handle, &[AttributeType::Value])
                .map_err(|e| {
                    HardmtlsError::Pkcs11Error(format!("Failed to get cert attributes: {e}"))
                })?;

            let Some(Attribute::Value(cert_der)) = attrs.first() else {
                return Err(HardmtlsError::CertificateError(
                    "Certificate value not found".into(),
                ));
            };

            let x509 = X509::from_der(cert_der).map_err(|e| {
                HardmtlsError::CertificateError(format!("Failed to parse DER: {e}"))
            })?;

            let pem = x509.to_pem().map_err(|e| {
                HardmtlsError::CertificateError(format!("Failed to convert to PEM: {e}"))
            })?;

            String::from_utf8(pem)
                .map_err(|e| HardmtlsError::CertificateError(format!("Invalid UTF-8 in PEM: {e}")))
        })
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
    fn invalid_slot_fails() {
        let config = Pkcs11Config {
            module: "dummy_module.so".to_string(),
            slot: "abc".to_string(),
            ..valid_config()
        };

        let backend = Pkcs11Backend::new(&config).unwrap();
        // Since we can't test a real session in unit tests without hardware/mocking,
        // this will either fail on module load or slot parse. Let's assume module fails to load first.
        let err = backend.sign(b"test").unwrap_err();
        match err {
            HardmtlsError::Pkcs11Error(msg) => {
                // Could be module not found or slot error depending on implementation
                assert!(msg.contains("Failed to load module") || msg.contains("Invalid slot"));
            }
            _ => panic!("Expected Pkcs11Error"),
        }
    }

    #[test]
    fn module_not_found_fails() {
        let config = Pkcs11Config {
            module: "does_not_exist_xyz.so".to_string(),
            ..valid_config()
        };
        let backend = Pkcs11Backend::new(&config).unwrap();
        let err = backend.certificate_pem().unwrap_err();
        match err {
            HardmtlsError::Pkcs11Error(msg) => assert!(msg.contains("Failed to load module")),
            _ => panic!("Expected Pkcs11Error"),
        }
    }
}
