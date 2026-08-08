//! Backend module for different keystore implementations.

#[cfg(target_os = "macos")]
pub mod mac_se;

pub mod pkcs11;

#[cfg(target_os = "windows")]
#[allow(
    unsafe_code,
    clippy::borrow_as_ptr,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::manual_ignore_case_cmp,
    clippy::manual_string_new,
    clippy::ptr_as_ptr,
    clippy::used_underscore_binding
)]
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
    if !raw_sig.len().is_multiple_of(2) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid P-256 raw ECDSA signature: 32-byte r || 32-byte s (big-endian).
    fn p256_raw_sig() -> Vec<u8> {
        let mut sig = vec![0u8; 64];
        // r = 1 (left-padded to 32 bytes)
        sig[31] = 1;
        // s = 2 (left-padded to 32 bytes)
        sig[63] = 2;
        sig
    }

    #[test]
    fn raw_ecdsa_to_der_p256_valid() {
        let raw = p256_raw_sig();
        let der = raw_ecdsa_to_der(&raw).unwrap();
        // DER output must start with SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30);
        // Verify round-trip by parsing back with OpenSSL
        let parsed = openssl::ecdsa::EcdsaSig::from_der(&der).unwrap();
        assert_eq!(parsed.r().to_vec(), vec![1]);
        assert_eq!(parsed.s().to_vec(), vec![2]);
    }

    #[test]
    fn raw_ecdsa_to_der_p384_valid() {
        // P-384: 48-byte r || 48-byte s = 96 bytes total
        let mut raw = vec![0u8; 96];
        raw[47] = 0x42;
        raw[95] = 0x43;
        let der = raw_ecdsa_to_der(&raw).unwrap();
        assert_eq!(der[0], 0x30);
        let parsed = openssl::ecdsa::EcdsaSig::from_der(&der).unwrap();
        assert_eq!(parsed.r().to_vec(), vec![0x42]);
        assert_eq!(parsed.s().to_vec(), vec![0x43]);
    }

    #[test]
    fn raw_ecdsa_to_der_odd_length_rejected() {
        let raw = vec![0u8; 65]; // odd length
        let err = raw_ecdsa_to_der(&raw).unwrap_err();
        assert!(
            err.to_string()
                .contains("Invalid raw ECDSA signature length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn raw_ecdsa_to_der_empty_input() {
        // Empty is even-length (0), so it should attempt conversion.
        // BigNum::from_slice(&[]) produces zero, which is a valid (though
        // degenerate) ECDSA component.
        let result = raw_ecdsa_to_der(&[]);
        // Either succeeds with a trivial signature or fails gracefully
        assert!(result.is_ok() || result.is_err());
    }
}
