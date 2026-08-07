//! Raw FFI declarations for OpenSSL Provider API types not exposed by `openssl-sys`.
//!
//! These types are needed to implement an OpenSSL 3.x Provider in Rust.
//! They are stable across OpenSSL 3.x (3.0 → 3.6+).

use std::ffi::{c_char, c_int, c_void};

/// OpenSSL dispatch table entry — maps a function ID to a function pointer.
///
/// The Provider returns arrays of these to register its implementations.
/// A sentinel entry with `function_id = 0` terminates each array.
#[repr(C)]
pub struct OsslDispatch {
    /// Function ID (e.g., `OSSL_FUNC_KEYMGMT_NEW`).
    pub function_id: c_int,
    /// Function pointer (cast from the appropriate `extern "C" fn`).
    pub function: Option<unsafe extern "C" fn()>,
}

// SAFETY: OsslDispatch contains only a c_int and a function pointer.
// Both are read-only static data, safe to share across threads.
#[allow(unsafe_code)]
unsafe impl Sync for OsslDispatch {}

/// OpenSSL algorithm descriptor — maps a name to a dispatch table.
#[repr(C)]
pub struct OsslAlgorithm {
    /// Algorithm name (e.g., `"hardmtls-key"`).
    pub algorithm_names: *const c_char,
    /// Property definition string (e.g., `"provider=hardmtls"`).
    pub property_definition: *const c_char,
    /// Dispatch table implementing this algorithm.
    pub implementation: *const OsslDispatch,
    /// Optional description string.
    pub algorithm_description: *const c_char,
}

// SAFETY: OsslAlgorithm contains only const pointers to static data.
// The algorithm tables are read-only and live for 'static.
#[allow(unsafe_code)]
unsafe impl Sync for OsslAlgorithm {}

// ── Provider init callback type ────────────────────────────────────────

/// Callback type for `OSSL_provider_init`.
///
/// This is the entry point OpenSSL calls when loading a provider.
pub type OsslProviderInitFn = unsafe extern "C" fn(
    handle: *const c_void,                  // OSSL_CORE_HANDLE
    in_dispatch: *const OsslDispatch,       // core functions
    out_dispatch: *mut *const OsslDispatch, // provider functions
    out_provctx: *mut *mut c_void,          // provider context
) -> c_int;

// ── OpenSSL constants for Provider operations ──────────────────────────
// Values from: openssl/core_dispatch.h (OpenSSL 3.6.3)

/// Operation ID for key management.
pub const OSSL_OP_KEYMGMT: c_int = 10;
/// Operation ID for signature.
pub const OSSL_OP_SIGNATURE: c_int = 12; // Not 11!

// KEYMGMT function IDs (from core_dispatch.h)
/// `keymgmt_new` — allocate a new key.
pub const OSSL_FUNC_KEYMGMT_NEW: c_int = 1;
/// `keymgmt_free` — free a key.
pub const OSSL_FUNC_KEYMGMT_FREE: c_int = 10;
/// `keymgmt_get_params` — get key metadata (bits, max-size, security-bits).
pub const OSSL_FUNC_KEYMGMT_GET_PARAMS: c_int = 11;
/// `keymgmt_gettable_params` — declare gettable key params.
pub const OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS: c_int = 12;
/// `keymgmt_set_params` — set key params.
pub const OSSL_FUNC_KEYMGMT_SET_PARAMS: c_int = 13;
/// `keymgmt_settable_params` — declare settable key params.
pub const OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS: c_int = 14;
/// `keymgmt_has` — query what parts the key has.
pub const OSSL_FUNC_KEYMGMT_HAS: c_int = 21;
/// `keymgmt_validate` — validate key consistency.
pub const OSSL_FUNC_KEYMGMT_VALIDATE: c_int = 22;
/// `keymgmt_match` — compare two keys.
pub const OSSL_FUNC_KEYMGMT_MATCH: c_int = 23;
/// `keymgmt_import` — import key data.
pub const OSSL_FUNC_KEYMGMT_IMPORT: c_int = 40;
/// `keymgmt_import_types` — declare importable types.
pub const OSSL_FUNC_KEYMGMT_IMPORT_TYPES: c_int = 41;
/// `keymgmt_export` — export key data (returns 0 for proxy keys).
pub const OSSL_FUNC_KEYMGMT_EXPORT: c_int = 42;
/// `keymgmt_export_types` — declare exportable types.
pub const OSSL_FUNC_KEYMGMT_EXPORT_TYPES: c_int = 43;
/// `keymgmt_dup` — duplicate a key.
pub const OSSL_FUNC_KEYMGMT_DUP: c_int = 44;

// SIGNATURE function IDs (from core_dispatch.h)
/// `signature_newctx` — allocate signing context.
pub const OSSL_FUNC_SIGNATURE_NEWCTX: c_int = 1;
/// `signature_sign_init` — initialize signing.
pub const OSSL_FUNC_SIGNATURE_SIGN_INIT: c_int = 2;
/// `signature_sign` — produce signature.
pub const OSSL_FUNC_SIGNATURE_SIGN: c_int = 3;
/// `signature_digest_sign_init` — init digest+sign.
pub const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT: c_int = 8;
/// `signature_digest_sign_update` — feed data.
pub const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE: c_int = 9;
/// `signature_digest_sign_final` — finalize digest+sign.
pub const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL: c_int = 10;
/// `signature_digest_sign` — one-shot digest+sign.
pub const OSSL_FUNC_SIGNATURE_DIGEST_SIGN: c_int = 11;
/// `signature_digest_verify_init` — init digest+verify.
pub const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT: c_int = 12;
/// `signature_digest_verify_update` — feed verify data.
pub const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE: c_int = 13;
/// `signature_digest_verify_final` — finalize digest+verify.
pub const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL: c_int = 14;
/// `signature_digest_verify` — one-shot digest+verify.
pub const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY: c_int = 15;
/// `signature_freectx` — free signing context.
pub const OSSL_FUNC_SIGNATURE_FREECTX: c_int = 16;
/// `signature_dupctx` — duplicate signing context.
pub const OSSL_FUNC_SIGNATURE_DUPCTX: c_int = 17;
/// `signature_get_ctx_params` — get context params.
pub const OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS: c_int = 18;
/// `signature_gettable_ctx_params` — declare gettable context params.
pub const OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS: c_int = 19;
/// `signature_set_ctx_params` — set context params.
pub const OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS: c_int = 20;
/// `signature_settable_ctx_params` — declare settable context params.
pub const OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS: c_int = 21;
/// `signature_get_ctx_md_params` — get digest context params.
pub const OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS: c_int = 22;
/// `signature_gettable_ctx_md_params` — declare gettable digest params.
pub const OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS: c_int = 23;
/// `signature_set_ctx_md_params` — set digest context params.
pub const OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS: c_int = 24;
/// `signature_settable_ctx_md_params` — declare settable digest params.
pub const OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS: c_int = 25;

// Key selection bits
/// The key has a private component.
pub const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// The key has a public component.
pub const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;

// OSSL_PARAM data types
/// Signed integer parameter.
pub const OSSL_PARAM_INTEGER: u32 = 1;
/// Octet string (arbitrary binary data).
pub const OSSL_PARAM_OCTET_STRING: u32 = 5;

/// Custom parameter key for passing the sign callback function pointer.
pub const HARDMTLS_PARAM_SIGN_FUNC: &std::ffi::CStr = c"hardmtls-sign-func";

/// Custom parameter key for passing key bit size during import.
pub const HARDMTLS_PARAM_KEY_BITS: &std::ffi::CStr = c"hardmtls-key-bits";
/// Custom parameter key for passing security bits during import.
pub const HARDMTLS_PARAM_SECURITY_BITS: &std::ffi::CStr = c"hardmtls-security-bits";
/// Custom parameter key for passing max signature size during import.
pub const HARDMTLS_PARAM_MAX_SIZE: &std::ffi::CStr = c"hardmtls-max-size";

// OpenSSL standard param names (from core_names.h)
/// Standard param: key bit size.
pub const OSSL_PKEY_PARAM_BITS: &std::ffi::CStr = c"bits";
/// Standard param: security strength in bits.
pub const OSSL_PKEY_PARAM_SECURITY_BITS: &std::ffi::CStr = c"security-bits";
/// Standard param: maximum signature size in bytes.
pub const OSSL_PKEY_PARAM_MAX_SIZE: &std::ffi::CStr = c"max-size";

// ── FFI declarations ───────────────────────────────────────────────────

extern "C" {
    /// Register a built-in provider (avoids loading a separate .so file).
    ///
    /// After calling this, `OSSL_PROVIDER_load(ctx, name)` will invoke
    /// `init_fn` instead of searching the filesystem.
    #[allow(unsafe_code)]
    pub fn OSSL_PROVIDER_add_builtin(
        ctx: *mut openssl_sys::OSSL_LIB_CTX,
        name: *const c_char,
        init_fn: OsslProviderInitFn,
    ) -> c_int;
}

// Sentinel value to terminate dispatch/algorithm arrays.
impl OsslDispatch {
    /// Create a sentinel entry that terminates a dispatch array.
    #[must_use]
    pub const fn end() -> Self {
        Self {
            function_id: 0,
            function: None,
        }
    }
}

impl OsslAlgorithm {
    /// Create a sentinel entry that terminates an algorithm array.
    #[must_use]
    pub const fn end() -> Self {
        Self {
            algorithm_names: std::ptr::null(),
            property_definition: std::ptr::null(),
            implementation: std::ptr::null(),
            algorithm_description: std::ptr::null(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_sentinel_has_zero_id() {
        let sentinel = OsslDispatch::end();
        assert_eq!(sentinel.function_id, 0);
        assert!(sentinel.function.is_none());
    }

    #[test]
    fn algorithm_sentinel_has_null_pointers() {
        let sentinel = OsslAlgorithm::end();
        assert!(sentinel.algorithm_names.is_null());
        assert!(sentinel.implementation.is_null());
    }

    #[test]
    fn dispatch_entry_can_hold_function() {
        extern "C" fn dummy() {}
        let entry = OsslDispatch {
            function_id: OSSL_FUNC_KEYMGMT_NEW,
            function: Some(dummy),
        };
        assert_eq!(entry.function_id, 1);
        assert!(entry.function.is_some());
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(OSSL_OP_KEYMGMT, 10);
        assert_eq!(OSSL_OP_SIGNATURE, 12);
    }
}
