//! Backend module for different keystore implementations.

#[cfg(target_os = "macos")]
pub mod mac_se;

pub mod pkcs11;

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
pub mod win_ncrypt;

use crate::error::HardmtlsError;
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;

/// A trait that defines the required behavior of a signing backend.
pub trait SigningBackend: Send + Sync {
    /// Sign the given `data` using the backend's private key.
    ///
    /// For EC keys, `data` is typically the SHA-256 digest of the TLS transcript.
    /// The returned signature must be properly DER encoded if ECDSA.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HardmtlsError>;

    /// Retrieve the matching certificate as a PEM string.
    fn certificate_pem(&self) -> Result<String, HardmtlsError>;
}

/// Helper function to convert a raw P-256/P-384 ECDSA signature (r || s, big-endian)
/// into an ASN.1 DER encoded ECDSA signature required by OpenSSL.
pub fn raw_ecdsa_to_der(raw_sig: &[u8]) -> Result<Vec<u8>, HardmtlsError> {
    if raw_sig.len() % 2 != 0 {
        return Err(HardmtlsError::Pkcs11Error(format!(
            "Invalid raw ECDSA signature length: {}",
            raw_sig.len()
        )));
    }

    let half = raw_sig.len() / 2;
    let r_bignum = BigNum::from_slice(&raw_sig[..half])
        .map_err(|e| HardmtlsError::Pkcs11Error(format!("Failed to parse r: {e}")))?;
    let s_bignum = BigNum::from_slice(&raw_sig[half..])
        .map_err(|e| HardmtlsError::Pkcs11Error(format!("Failed to parse s: {e}")))?;

    let sig = EcdsaSig::from_private_components(r_bignum, s_bignum)
        .map_err(|e| HardmtlsError::Pkcs11Error(format!("Failed to create EcdsaSig: {e}")))?;

    sig.to_der()
        .map_err(|e| HardmtlsError::Pkcs11Error(format!("Failed to encode DER: {e}")))
}
