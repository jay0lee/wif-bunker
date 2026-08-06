//! Parses and loads the hardmTLS certificate configuration.

use crate::error::HardmtlsError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Top-level configuration for hardmTLS certificates and libraries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    /// Configuration format version.
    pub version: u32,
    /// Available certificate configurations for different backends.
    pub cert_configs: CertConfigs,
    /// Library paths.
    pub libs: LibsConfig,
}

/// Contains optional configurations for various cryptographic backends.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertConfigs {
    /// PKCS#11 module configuration.
    #[serde(default)]
    pub pkcs11: Option<Pkcs11Config>,
    /// Windows Certificate Store configuration.
    #[serde(default)]
    pub windows_store: Option<WindowsStoreConfig>,
    /// macOS Keychain configuration.
    #[serde(default)]
    pub macos_keychain: Option<MacosKeychainConfig>,
    /// Workload identity or file-based certificate configuration.
    #[serde(default)]
    pub workload: Option<WorkloadConfig>,
}

/// Configuration for a PKCS#11 backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pkcs11Config {
    /// Path to the PKCS#11 module library.
    pub module: String,
    /// Slot identifier.
    pub slot: String,
    /// Label of the token or key.
    pub label: String,
    /// User PIN for the token.
    pub user_pin: String,
}

/// Configuration for the Windows Certificate Store backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsStoreConfig {
    /// Name of the store (e.g., "MY").
    pub store: String,
    /// Provider context (e.g., `current_user`).
    pub provider: String,
    /// Issuer string to match.
    pub issuer: String,
}

/// Configuration for the macOS Keychain backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosKeychainConfig {
    /// Issuer string to match.
    pub issuer: String,
}

/// Configuration for a workload or file-based certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadConfig {
    /// Path to the PEM-encoded certificate.
    pub cert_path: String,
}

/// Paths to dynamically loaded libraries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibsConfig {
    /// Path to the ECP client library.
    pub ecp_client: String,
    /// Path to the TLS offload library.
    pub tls_offload: String,
}

/// Loads a `CertificateConfig` from a specified JSON file path.
///
/// # Errors
///
/// Returns `HardmtlsError` if the file cannot be read, or if it fails to parse as valid JSON.
pub fn load_from_file(path: &str) -> Result<CertificateConfig, HardmtlsError> {
    let file_path = Path::new(path);
    let contents = fs::read_to_string(file_path).map_err(HardmtlsError::ConfigReadError)?;
    let config: CertificateConfig =
        serde_json::from_str(&contents).map_err(HardmtlsError::ConfigParseError)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_full_config() {
        let json_data = r#"{
            "version": 1,
            "cert_configs": {
                "pkcs11": {
                    "module": "/usr/lib/libpkcs11.so",
                    "slot": "0",
                    "label": "MyToken",
                    "user_pin": "123456"
                },
                "windows_store": {
                    "store": "MY",
                    "provider": "current_user",
                    "issuer": "CN=Test CA"
                },
                "macos_keychain": {
                    "issuer": "CN=Apple CA"
                },
                "workload": {
                    "cert_path": "/var/run/secrets/cert.pem"
                }
            },
            "libs": {
                "ecp_client": "/opt/hardmtls/libecp.so",
                "tls_offload": "/opt/hardmtls/libtls.so"
            }
        }"#;

        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        write!(file, "{json_data}").expect("Failed to write to temp file");

        let config = load_from_file(file.path().to_str().unwrap()).expect("Failed to load config");
        assert_eq!(config.version, 1);

        let pkcs11 = config.cert_configs.pkcs11.expect("Missing pkcs11 config");
        assert_eq!(pkcs11.module, "/usr/lib/libpkcs11.so");
        assert_eq!(pkcs11.slot, "0");

        let macos = config
            .cert_configs
            .macos_keychain
            .expect("Missing macos config");
        assert_eq!(macos.issuer, "CN=Apple CA");

        assert_eq!(config.libs.ecp_client, "/opt/hardmtls/libecp.so");
    }

    #[test]
    fn test_load_partial_config() {
        let json_data = r#"{
            "version": 2,
            "cert_configs": {
                "workload": {
                    "cert_path": "/path/to/cert.pem"
                }
            },
            "libs": {
                "ecp_client": "ecp.so",
                "tls_offload": "tls.so"
            }
        }"#;

        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        write!(file, "{json_data}").expect("Failed to write to temp file");

        let config = load_from_file(file.path().to_str().unwrap()).expect("Failed to load config");
        assert!(config.cert_configs.pkcs11.is_none());
        assert!(config.cert_configs.windows_store.is_none());
        assert!(config.cert_configs.macos_keychain.is_none());
        assert!(config.cert_configs.workload.is_some());
        assert_eq!(
            config.cert_configs.workload.unwrap().cert_path,
            "/path/to/cert.pem"
        );
    }

    #[test]
    fn test_load_missing_file() {
        let err = load_from_file("/this/path/does/not/exist.json").unwrap_err();
        match err {
            HardmtlsError::ConfigReadError(_) => (),
            _ => panic!("Expected ConfigReadError, got: {err:?}"),
        }
    }

    #[test]
    fn test_load_invalid_json() {
        let json_data = r#"{ "version": 1, "cert_configs": { "#;
        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        write!(file, "{json_data}").expect("Failed to write to temp file");

        let err = load_from_file(file.path().to_str().unwrap()).unwrap_err();
        match err {
            HardmtlsError::ConfigParseError(_) => (),
            _ => panic!("Expected ConfigParseError, got: {err:?}"),
        }
    }
}
