//! Dispatch logic for selecting the appropriate signing backend.

use crate::backends::SigningBackend;
use crate::config::CertificateConfig;
use crate::error::HardmtlsError;

/// Select and instantiate the appropriate signing backend based on configuration.
///
/// Examines `cert_configs` to determine which backend to use:
/// 1. `pkcs11` → [`Pkcs11Backend`](crate::backends::pkcs11::Pkcs11Backend) (all platforms)
/// 2. `windows_store` → `NcryptBackend` (Windows only)
/// 3. `macos_keychain` → [`MacSeBackend`](crate::backends::mac_se::MacSeBackend) (macOS only)
///
/// # Errors
///
/// Returns [`HardmtlsError::BackendNotFound`] if no suitable backend configuration
/// is present, or if the platform does not support the requested backend.
pub fn select_backend(
    config: &CertificateConfig,
) -> Result<Box<dyn SigningBackend>, HardmtlsError> {
    log::debug!("hardmTLS: selecting signing backend from cert_configs...");

    // PKCS#11 is cross-platform — check first.
    if let Some(ref pkcs11_config) = config.cert_configs.pkcs11 {
        log::info!(
            "hardmTLS: using PKCS#11 backend (module={}, slot={}, label={})",
            pkcs11_config.module,
            pkcs11_config.slot,
            pkcs11_config.label,
        );
        let backend = crate::backends::pkcs11::Pkcs11Backend::new(pkcs11_config)?;
        return Ok(Box::new(backend));
    }

    // Windows NCrypt — only available on Windows.
    #[cfg(target_os = "windows")]
    if let Some(ref win_config) = config.cert_configs.windows_store {
        log::info!(
            "hardmTLS: using Windows NCrypt backend (store={}, issuer={})",
            win_config.store,
            win_config.issuer,
        );
        let backend = crate::backends::win_ncrypt::NcryptBackend::new(win_config)?;
        return Ok(Box::new(backend));
    }

    // macOS Security.framework — only available on macOS.
    #[cfg(target_os = "macos")]
    if let Some(ref mac_config) = config.cert_configs.macos_keychain {
        log::info!(
            "hardmTLS: using macOS Keychain backend (issuer={})",
            mac_config.issuer,
        );
        let backend = crate::backends::mac_se::MacSeBackend::new(mac_config)?;
        return Ok(Box::new(backend));
    }

    log::error!(
        "hardmTLS: no matching backend found (pkcs11={}, windows_store={}, macos_keychain={})",
        config.cert_configs.pkcs11.is_some(),
        config.cert_configs.windows_store.is_some(),
        config.cert_configs.macos_keychain.is_some(),
    );
    Err(HardmtlsError::BackendNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_returns_backend_not_found() {
        let json = r#"{
            "version": 1,
            "cert_configs": {},
            "libs": { "ecp_client": "/dev/null", "tls_offload": "/dev/null" }
        }"#;
        let config: CertificateConfig = serde_json::from_str(json).unwrap();
        let result = select_backend(&config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            matches!(err, HardmtlsError::BackendNotFound),
            "Expected BackendNotFound, got {err:?}"
        );
    }

    #[test]
    fn pkcs11_config_selects_pkcs11_backend() {
        let json = r#"{
            "version": 1,
            "cert_configs": {
                "pkcs11": {
                    "module": "/usr/lib/libykcs11.so",
                    "slot": "0",
                    "label": "test",
                    "user_pin": "1234"
                }
            },
            "libs": { "ecp_client": "/dev/null", "tls_offload": "/dev/null" }
        }"#;
        let config: CertificateConfig = serde_json::from_str(json).unwrap();
        // Should succeed (returns a Pkcs11Backend, even though sign() is stubbed)
        let backend = select_backend(&config);
        assert!(backend.is_ok(), "PKCS#11 config should select a backend");
    }

    #[test]
    fn pkcs11_empty_module_returns_error() {
        let json = r#"{
            "version": 1,
            "cert_configs": {
                "pkcs11": {
                    "module": "",
                    "slot": "0",
                    "label": "test",
                    "user_pin": "1234"
                }
            },
            "libs": { "ecp_client": "/dev/null", "tls_offload": "/dev/null" }
        }"#;
        let config: CertificateConfig = serde_json::from_str(json).unwrap();
        let result = select_backend(&config);
        assert!(result.is_err(), "Empty module should fail");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_keychain_config_selects_mac_se_backend() {
        let json = r#"{
            "version": 1,
            "cert_configs": {
                "macos_keychain": { "issuer": "My CA" }
            },
            "libs": { "ecp_client": "/dev/null", "tls_offload": "/dev/null" }
        }"#;
        let config: CertificateConfig = serde_json::from_str(json).unwrap();
        let backend = select_backend(&config);
        assert!(backend.is_ok(), "macOS config should select a backend");
    }
}
