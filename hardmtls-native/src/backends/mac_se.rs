//! macOS Security.framework backend for hardmTLS.
//!
//! This module provides the implementation of `SigningBackend` for macOS,
//! utilizing the Security.framework to interface with hardware keys stored
//! in the Secure Enclave and Keychain.
//!
//! ## Identity Lookup
//!
//! The backend searches for identities (cert + private key pairs) in the
//! default keychain. It matches certificates whose **issuer** string contains
//! the configured issuer value.
//!
//! ## Signing
//!
//! google-auth pre-hashes with SHA256 before calling `SignForPython`, so our
//! `sign()` method receives a 32-byte SHA256 digest.  We use the algorithm
//! `kSecKeyAlgorithmECDSASignatureDigestX962SHA256` which signs a pre-computed
//! digest without re-hashing.

use crate::backends::SigningBackend;
use crate::config::MacosKeychainConfig;
use crate::error::HardmtlsError;

use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::key::Algorithm;

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

    /// Find the Keychain identity whose certificate's issuer matches.
    ///
    /// Searches all identities in the default keychain, extracts each
    /// certificate's issuer string, and returns the first identity whose
    /// issuer contains `self.issuer`.
    fn find_identity(&self) -> Result<security_framework::identity::SecIdentity, HardmtlsError> {
        let results = ItemSearchOptions::new()
            .class(ItemClass::identity())
            .load_refs(true)
            .limit(Limit::All)
            .search()
            .map_err(|e| {
                HardmtlsError::SecurityFrameworkError(format!(
                    "Keychain identity search failed: {e}"
                ))
            })?;

        for result in results {
            if let SearchResult::Ref(Reference::Identity(identity)) = result {
                // Get the certificate from this identity.
                let cert = identity.certificate().map_err(|e| {
                    HardmtlsError::SecurityFrameworkError(format!(
                        "failed to get certificate from identity: {e}"
                    ))
                })?;

                // Parse the cert DER to check the issuer.
                let der_bytes = cert.to_der();
                if issuer_matches(&der_bytes, &self.issuer) {
                    return Ok(identity);
                }
            }
        }

        Err(HardmtlsError::SecurityFrameworkError(format!(
            "no identity found with issuer matching '{}'",
            self.issuer
        )))
    }
}

/// Check whether a DER-encoded certificate's issuer contains the given string.
///
/// Uses OpenSSL to parse the certificate and extract the issuer's `oneline`
/// representation, then does a substring match.
fn issuer_matches(der: &[u8], issuer_substring: &str) -> bool {
    let Ok(x509) = openssl::x509::X509::from_der(der) else {
        return false;
    };

    // issuer_name().entries() gives us individual RDN components.
    // The `oneline()` representation is like "/CN=Foo/O=Bar".
    // We check if any entry's value contains our search string.
    for entry in x509.issuer_name().entries() {
        if let Ok(val) = entry.data().to_string() {
            if val.contains(issuer_substring) {
                return true;
            }
        }
    }

    // Also check the full oneline representation.
    let oneline = x509
        .issuer_name()
        .entries()
        .filter_map(|e| e.data().to_string().ok())
        .collect::<Vec<_>>()
        .join(" ");
    oneline.contains(issuer_substring)
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

impl SigningBackend for MacSeBackend {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HardmtlsError> {
        let identity = self.find_identity()?;
        let key = identity.private_key().map_err(|e| {
            HardmtlsError::SecurityFrameworkError(format!(
                "failed to get private key from identity: {e}"
            ))
        })?;

        // google-auth pre-hashes with SHA256, so `data` is a 32-byte digest.
        // Use the "digest" algorithm variant that signs the raw digest
        // without re-hashing.
        key.create_signature(Algorithm::ECDSASignatureDigestX962SHA256, data)
            .map_err(|e| {
                HardmtlsError::SecurityFrameworkError(format!("SecKeyCreateSignature failed: {e}"))
            })
    }

    fn certificate_pem(&self) -> Result<String, HardmtlsError> {
        let identity = self.find_identity()?;
        let cert = identity.certificate().map_err(|e| {
            HardmtlsError::SecurityFrameworkError(format!(
                "failed to get certificate from identity: {e}"
            ))
        })?;
        der_to_pem(&cert.to_der())
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

    /// Helper: generate a self-signed RSA cert with the given CN.
    /// Uses RSA to avoid our hardmTLS EC provider intercepting the signing.
    fn make_test_cert(cn: &str) -> Vec<u8> {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", cn).unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build().to_der().unwrap()
    }

    #[test]
    fn test_issuer_matches_self_signed() {
        let der = make_test_cert("Test Issuer");
        assert!(issuer_matches(&der, "Test Issuer"));
        assert!(!issuer_matches(&der, "Wrong Issuer"));
    }

    #[test]
    fn test_der_to_pem() {
        let der = make_test_cert("Test");
        let pem = der_to_pem(&der).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
    }

    #[test]
    fn test_no_matching_identity() {
        // This should fail because no identity matches this issuer.
        let config = MacosKeychainConfig {
            issuer: "CN=Definitely-Not-In-Keychain-12345".to_string(),
        };
        let backend = MacSeBackend::new(&config).unwrap();
        let result = backend.certificate_pem();
        assert!(result.is_err());
    }
}
