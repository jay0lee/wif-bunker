//! Defines the core error types for the hardmTLS project.

use thiserror::Error;

/// Core error type for the hardmTLS library.
#[derive(Error, Debug)]
pub enum HardmtlsError {
    /// The configuration path provided is not valid UTF-8.
    #[error("Configuration path is not valid UTF-8")]
    InvalidConfigPath,

    /// Failed to read the configuration file from disk.
    #[error("Failed to read config file: {0}")]
    ConfigReadError(#[from] std::io::Error),

    /// Failed to parse the configuration file as JSON.
    #[error("Failed to parse config JSON: {0}")]
    ConfigParseError(#[from] serde_json::Error),

    /// No supported backend could be found in the configuration.
    #[error("No supported backend found in config")]
    BackendNotFound,

    /// A PKCS#11 operation failed.
    #[error("PKCS#11 error: {0}")]
    Pkcs11Error(String),

    /// A Windows `NCrypt` operation failed.
    #[error("NCrypt error: {0}")]
    NcryptError(String),

    /// A macOS Security.framework operation failed.
    #[error("SecurityFramework error: {0}")]
    SecurityFrameworkError(String),

    /// An OpenSSL operation failed.
    #[error("OpenSSL error: {0}")]
    SslError(String),

    /// General signing failure.
    #[error("Signing error: {0}")]
    SigningError(String),

    /// Certificate retrieval or parsing failed.
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// The output buffer was too small to hold the requested data.
    #[error("Buffer too small: needed {needed} bytes, but only {provided} were provided")]
    BufferTooSmall {
        /// The number of bytes required to store the result.
        needed: usize,
        /// The number of bytes that were actually provided.
        provided: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = HardmtlsError::InvalidConfigPath;
        assert_eq!(err.to_string(), "Configuration path is not valid UTF-8");

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = HardmtlsError::ConfigReadError(io_err);
        assert_eq!(
            err.to_string(),
            "Failed to read config file: file not found"
        );

        let parse_err_str = "{\"malformed\": ";
        let json_err = serde_json::from_str::<serde_json::Value>(parse_err_str).unwrap_err();
        let err = HardmtlsError::ConfigParseError(json_err);
        assert!(err.to_string().starts_with("Failed to parse config JSON:"));

        let err = HardmtlsError::BackendNotFound;
        assert_eq!(err.to_string(), "No supported backend found in config");

        let err = HardmtlsError::Pkcs11Error("token not present".to_string());
        assert_eq!(err.to_string(), "PKCS#11 error: token not present");

        let err = HardmtlsError::NcryptError("invalid handle".to_string());
        assert_eq!(err.to_string(), "NCrypt error: invalid handle");

        let err = HardmtlsError::SecurityFrameworkError("item not found".to_string());
        assert_eq!(err.to_string(), "SecurityFramework error: item not found");

        let err = HardmtlsError::SslError("malloc failure".to_string());
        assert_eq!(err.to_string(), "OpenSSL error: malloc failure");

        let err = HardmtlsError::SigningError("invalid digest size".to_string());
        assert_eq!(err.to_string(), "Signing error: invalid digest size");

        let err = HardmtlsError::CertificateError("expired".to_string());
        assert_eq!(err.to_string(), "Certificate error: expired");

        let err = HardmtlsError::BufferTooSmall {
            needed: 256,
            provided: 128,
        };
        assert_eq!(
            err.to_string(),
            "Buffer too small: needed 256 bytes, but only 128 were provided"
        );
    }
}
