//! OpenSSL Provider implementation for hardmTLS.
//!
//! Registers a custom OpenSSL Provider (`hardmtls`) that implements
//! `KEYMGMT` and `SIGNATURE` operations. This allows us to create
//! `EVP_PKEY` objects backed by our hardware signing callback, which
//! OpenSSL uses transparently during TLS handshakes.
//!
//! # Architecture
//!
//! ```text
//! OSSL_PROVIDER_add_builtin("hardmtls", init)
//!         │
//!         ▼
//! OSSL_provider_init
//!   ├── KEYMGMT "RSA" + "EC"
//!   │     new/free/has/import/match/get_params/validate/export/dup
//!   └── SIGNATURE "RSA" + "EC"
//!         newctx/freectx/sign_init/sign/digest_sign/dupctx/...
//! ```

use std::ffi::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use std::sync::Once;

use crate::provider_ffi::{
    OsslAlgorithm, OsslDispatch, OSSL_PROVIDER_add_builtin,
    // KEYMGMT function IDs
    OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
    OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_SET_PARAMS,
    OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_VALIDATE,
    // SIGNATURE function IDs
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
    OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX,
    OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SIGN,
    OSSL_FUNC_SIGNATURE_SIGN_INIT,
    // Operation IDs
    OSSL_OP_KEYMGMT, OSSL_OP_SIGNATURE,
};
use crate::SignCallback;

/// Ensures the provider is registered exactly once.
static PROVIDER_INIT: Once = Once::new();

// ── Provider name (null-terminated) ────────────────────────────────────

/// Provider name used in `OSSL_PROVIDER_add_builtin`.
const PROVIDER_NAME: &std::ffi::CStr = c"hardmtls";

/// Algorithm name for RSA key type.
const RSA_ALG_NAME: &std::ffi::CStr = c"RSA";

/// Algorithm name for EC key type.
const EC_ALG_NAME: &std::ffi::CStr = c"EC";

/// Property definition for our algorithms.
///
/// The `hardmtls.sign=yes` property prevents our RSA/EC implementations from
/// being returned for default lookups (e.g., cert generation). OpenSSL only
/// returns our implementations when the property query explicitly includes
/// `hardmtls.sign=yes` or when looking up from our provider specifically
/// (which happens automatically for keys created by our keymgmt).
const PROVIDER_PROPS: &std::ffi::CStr = c"provider=hardmtls,hardmtls.sign=yes";

// ── Key data (stored inside EVP_PKEY via KEYMGMT) ──────────────────────

/// Internal key representation stored by our KEYMGMT.
///
/// Holds the signing callback that delegates to google-auth's
/// `SignForPython` wrapper, plus key metadata needed by `EVP_PKEY_get_size()`
/// and other introspection APIs.
struct HardmtlsKey {
    /// The signing callback provided by the caller.
    /// `None` after `keymgmt_new`, populated by `keymgmt_import`.
    sign_func: Option<SignCallback>,
    /// Key size in bits (e.g., 2048 for RSA-2048, 256 for P-256).
    key_bits: c_int,
    /// Security strength in bits (e.g., 112 for RSA-2048, 128 for P-256).
    security_bits: c_int,
    /// Maximum signature size in bytes (e.g., 256 for RSA-2048, 72 for P-256).
    max_sig_size: c_int,
}

// ── Signing context (stored by SIGNATURE operations) ───────────────────

/// Context for an in-progress signing operation.
struct HardmtlsSignCtx {
    /// Reference to the key (borrowed, not owned — OpenSSL manages lifetime).
    key: *const HardmtlsKey,
    /// Accumulated data for `digest_sign` (init/update/final) path.
    /// The sign callback handles hashing internally, so we buffer all data
    /// and pass it in one shot on `digest_sign_final`.
    tbs_buffer: Vec<u8>,
}

// ═══════════════════════════════════════════════════════════════════════
// KEYMGMT dispatch functions
// ═══════════════════════════════════════════════════════════════════════

/// Allocate a new (empty) key. The key is populated later via `import`.
#[allow(unsafe_code)]
extern "C" fn keymgmt_new(_provctx: *mut c_void) -> *mut c_void {
    let key = Box::new(HardmtlsKey {
        sign_func: None,
        key_bits: 0,
        security_bits: 0,
        max_sig_size: 0,
    });
    Box::into_raw(key).cast::<c_void>()
}

/// Free a key previously allocated by `keymgmt_new`.
#[allow(unsafe_code)]
extern "C" fn keymgmt_free(keydata: *mut c_void) {
    if !keydata.is_null() {
        // SAFETY: keydata was allocated by Box::into_raw in `keymgmt_new`.
        let _ = unsafe { Box::from_raw(keydata.cast::<HardmtlsKey>()) };
    }
}

/// Query what components the key has.
#[allow(unsafe_code)]
extern "C" fn keymgmt_has(keydata: *const c_void, _selection: c_int) -> c_int {
    if keydata.is_null() {
        return 0;
    }
    // Our key is a proxy — report that it has everything the caller asks about.
    // This allows SSL_CTX_use_PrivateKey to accept it for any key type.
    1
}

/// Import key data from an `OSSL_PARAM` array.
///
/// When called with our custom parameters, stores the signing callback and
/// key metadata. When called without them (e.g., during cross-provider key
/// comparison), succeeds silently — the temporary key is only used for matching.
#[allow(unsafe_code)]
extern "C" fn keymgmt_import(
    keydata: *mut c_void,
    _selection: c_int,
    params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    if keydata.is_null() || params.is_null() {
        return 0;
    }

    // SAFETY: keydata is valid (from keymgmt_new), we have exclusive access.
    let key = unsafe { &mut *keydata.cast::<HardmtlsKey>() };

    // SAFETY: params is valid and null-terminated (OpenSSL contract).
    let sign_func = unsafe { extract_sign_func_from_params(params) };

    if let Some(func) = sign_func {
        key.sign_func = Some(func);
        log::debug!("hardmTLS provider: imported sign_func into key");
    } else {
        // No sign_func — this is a comparison import (OpenSSL importing
        // a cert's public key into our keymgmt for matching). That's fine.
        log::debug!("hardmTLS provider: import without sign_func (comparison key)");
    }

    // Extract key metadata if present.
    unsafe { extract_key_metadata_from_params(params, key) };

    1 // Always succeed
}

/// Declare the types of parameters that `keymgmt_import` accepts.
///
/// OpenSSL requires this whenever `keymgmt_import` is provided (the import
/// function count must be exactly 2: `import` + `import_types`).
#[allow(unsafe_code)]
extern "C" fn keymgmt_import_types(_selection: c_int) -> *const openssl_sys::OSSL_PARAM {
    use crate::provider_ffi::{
        HARDMTLS_PARAM_KEY_BITS, HARDMTLS_PARAM_MAX_SIZE, HARDMTLS_PARAM_SECURITY_BITS,
        HARDMTLS_PARAM_SIGN_FUNC, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING,
    };

    /// Wrapper to allow `OSSL_PARAM` array in a static.
    struct SyncParams([openssl_sys::OSSL_PARAM; 5]);

    // SAFETY: OSSL_PARAM contains raw pointers that point to static data
    // (CStr literals and null). These are immutable and valid for 'static.
    #[allow(unsafe_code)]
    unsafe impl Sync for SyncParams {}

    static IMPORT_PARAMS: SyncParams = SyncParams([
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_SIGN_FUNC.as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data: std::ptr::null_mut(),
            data_size: std::mem::size_of::<SignCallback>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_KEY_BITS.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: std::ptr::null_mut(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_SECURITY_BITS.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: std::ptr::null_mut(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_MAX_SIZE.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: std::ptr::null_mut(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        // Sentinel.
        openssl_sys::OSSL_PARAM {
            key: std::ptr::null(),
            data_type: 0,
            data: std::ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
    ]);

    IMPORT_PARAMS.0.as_ptr()
}

/// Match two keys. Always returns 1 (match) because:
/// - The cert and key come from the same hardware token
/// - The caller (`configure_ssl_context`) guarantees they match
/// - We are a pass-through provider and don't have the actual key material
#[allow(unsafe_code)]
extern "C" fn keymgmt_match(
    _keydata1: *const c_void,
    _keydata2: *const c_void,
    _selection: c_int,
) -> c_int {
    log::debug!("hardmTLS provider: keymgmt_match called (always matches)");
    1
}

/// Get key metadata parameters (bits, security-bits, max-size).
///
/// This is the **root cause fix** — `EVP_PKEY_get_size()` calls this to
/// determine the maximum signature size. Without it, `EVP_PKEY_get_size()`
/// returns 0, causing TLS 1.3 to reject RSA-PSS signature algorithms.
#[allow(unsafe_code)]
extern "C" fn keymgmt_get_params(
    keydata: *const c_void,
    params: *mut openssl_sys::OSSL_PARAM,
) -> c_int {
    use crate::provider_ffi::{
        OSSL_PARAM_INTEGER, OSSL_PKEY_PARAM_BITS, OSSL_PKEY_PARAM_MAX_SIZE,
        OSSL_PKEY_PARAM_SECURITY_BITS,
    };

    if keydata.is_null() || params.is_null() {
        return 0;
    }

    // SAFETY: keydata is valid (from keymgmt_new/import).
    let key = unsafe { &*keydata.cast::<HardmtlsKey>() };

    // Walk the params array and fill in requested values.
    let mut i = 0;
    loop {
        // SAFETY: params is a valid, null-terminated OSSL_PARAM array.
        let param = unsafe { &mut *params.add(i) };
        if param.key.is_null() {
            break;
        }

        // SAFETY: key is a valid C string (OpenSSL contract).
        let key_bytes = unsafe { std::ffi::CStr::from_ptr(param.key) }.to_bytes();

        if param.data_type == OSSL_PARAM_INTEGER && !param.data.is_null() {
            if key_bytes == OSSL_PKEY_PARAM_BITS.to_bytes() {
                unsafe { write_int_param(param, key.key_bits) };
            } else if key_bytes == OSSL_PKEY_PARAM_MAX_SIZE.to_bytes() {
                unsafe { write_int_param(param, key.max_sig_size) };
            } else if key_bytes == OSSL_PKEY_PARAM_SECURITY_BITS.to_bytes() {
                unsafe { write_int_param(param, key.security_bits) };
            }
        }

        i += 1;
    }

    1
}

/// Declare the gettable key parameters.
#[allow(unsafe_code)]
extern "C" fn keymgmt_gettable_params(_provctx: *mut c_void) -> *const openssl_sys::OSSL_PARAM {
    use crate::provider_ffi::{
        OSSL_PARAM_INTEGER, OSSL_PKEY_PARAM_BITS, OSSL_PKEY_PARAM_MAX_SIZE,
        OSSL_PKEY_PARAM_SECURITY_BITS,
    };

    struct SyncParams([openssl_sys::OSSL_PARAM; 4]);

    #[allow(unsafe_code)]
    unsafe impl Sync for SyncParams {}

    static GETTABLE_PARAMS: SyncParams = SyncParams([
        openssl_sys::OSSL_PARAM {
            key: OSSL_PKEY_PARAM_BITS.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: std::ptr::null_mut(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: OSSL_PKEY_PARAM_MAX_SIZE.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: std::ptr::null_mut(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: OSSL_PKEY_PARAM_SECURITY_BITS.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: std::ptr::null_mut(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        // Sentinel.
        openssl_sys::OSSL_PARAM {
            key: std::ptr::null(),
            data_type: 0,
            data: std::ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
    ]);

    GETTABLE_PARAMS.0.as_ptr()
}

/// Set key parameters (no-op — keys are immutable after import).
#[allow(unsafe_code)]
extern "C" fn keymgmt_set_params(
    _keydata: *mut c_void,
    _params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    1
}

/// Declare settable key parameters (empty — keys are immutable after import).
#[allow(unsafe_code)]
extern "C" fn keymgmt_settable_params(_provctx: *mut c_void) -> *const openssl_sys::OSSL_PARAM {
    empty_param_list()
}

/// Validate a key (always valid — proxy key).
#[allow(unsafe_code)]
extern "C" fn keymgmt_validate(
    _keydata: *const c_void,
    _selection: c_int,
    _checktype: c_int,
) -> c_int {
    1
}

/// Export key data. Returns 0 (failure) because our proxy keys cannot be
/// meaningfully exported to another keymgmt — the sign callback function
/// pointer is process-local and has no portable representation.
///
/// Returning 0 is intentional and critical: in `do_sigver_init` iteration 1,
/// OpenSSL tries to export our key to the default provider's keymgmt. If
/// export succeeds, the default keymgmt creates a broken key. Returning 0
/// causes iteration 1 to fail cleanly, and iteration 2 uses our provider
/// directly (the correct path).
#[allow(unsafe_code)]
extern "C" fn keymgmt_export(
    _keydata: *const c_void,
    _selection: c_int,
    _export_cb: Option<
        unsafe extern "C" fn(
            *const openssl_sys::OSSL_PARAM,
            *mut c_void,
        ) -> c_int,
    >,
    _cbarg: *mut c_void,
) -> c_int {
    log::debug!("hardmTLS provider: keymgmt_export called (returning 0 — proxy key)");
    0
}

/// Declare exportable types (empty — proxy keys cannot be exported).
#[allow(unsafe_code)]
extern "C" fn keymgmt_export_types(_selection: c_int) -> *const openssl_sys::OSSL_PARAM {
    empty_param_list()
}

/// Duplicate a key.
#[allow(unsafe_code)]
extern "C" fn keymgmt_dup(
    keydata: *const c_void,
    _selection: c_int,
) -> *mut c_void {
    if keydata.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: keydata is valid (from keymgmt_new).
    let src = unsafe { &*keydata.cast::<HardmtlsKey>() };
    let dup = Box::new(HardmtlsKey {
        sign_func: src.sign_func,
        key_bits: src.key_bits,
        security_bits: src.security_bits,
        max_sig_size: src.max_sig_size,
    });
    Box::into_raw(dup).cast::<c_void>()
}

// ── KEYMGMT helpers ────────────────────────────────────────────────────

/// Extract the `SignCallback` function pointer from an `OSSL_PARAM` array.
///
/// Walks the array looking for a parameter named `"hardmtls-sign-func"` with
/// type `OSSL_PARAM_OCTET_STRING` and size `sizeof(SignCallback)`.
///
/// # Safety
///
/// `params` must be a valid, null-terminated `OSSL_PARAM` array.
#[allow(unsafe_code)]
unsafe fn extract_sign_func_from_params(
    params: *const openssl_sys::OSSL_PARAM,
) -> Option<SignCallback> {
    use crate::provider_ffi::{HARDMTLS_PARAM_SIGN_FUNC, OSSL_PARAM_OCTET_STRING};

    let target_key = HARDMTLS_PARAM_SIGN_FUNC.to_bytes();
    let expected_size = std::mem::size_of::<SignCallback>();

    // Walk the param array. It's terminated by an entry with key == NULL.
    let mut i = 0;
    loop {
        // SAFETY: params is valid and null-terminated.
        let param = unsafe { &*params.add(i) };
        if param.key.is_null() {
            break;
        }

        // SAFETY: key is a valid C string (OpenSSL contract).
        let key_bytes = unsafe { std::ffi::CStr::from_ptr(param.key) }.to_bytes();

        if key_bytes == target_key
            && param.data_type == OSSL_PARAM_OCTET_STRING
            && param.data_size == expected_size
            && !param.data.is_null()
        {
            // SAFETY: data points to `expected_size` bytes containing a SignCallback.
            let func: SignCallback = unsafe { std::ptr::read(param.data.cast::<SignCallback>()) };
            return Some(func);
        }

        i += 1;
    }

    None
}

/// Extract key metadata (bits, security_bits, max_sig_size) from params.
///
/// # Safety
///
/// `params` must be a valid, null-terminated `OSSL_PARAM` array.
/// `key` must be a valid mutable reference.
#[allow(unsafe_code)]
unsafe fn extract_key_metadata_from_params(
    params: *const openssl_sys::OSSL_PARAM,
    key: &mut HardmtlsKey,
) {
    use crate::provider_ffi::{
        HARDMTLS_PARAM_KEY_BITS, HARDMTLS_PARAM_MAX_SIZE, HARDMTLS_PARAM_SECURITY_BITS,
        OSSL_PARAM_INTEGER,
    };

    let mut i = 0;
    loop {
        let param = unsafe { &*params.add(i) };
        if param.key.is_null() {
            break;
        }

        let key_bytes = unsafe { std::ffi::CStr::from_ptr(param.key) }.to_bytes();

        if param.data_type == OSSL_PARAM_INTEGER && !param.data.is_null() {
            if key_bytes == HARDMTLS_PARAM_KEY_BITS.to_bytes() {
                key.key_bits = unsafe { read_int_param(param) };
            } else if key_bytes == HARDMTLS_PARAM_SECURITY_BITS.to_bytes() {
                key.security_bits = unsafe { read_int_param(param) };
            } else if key_bytes == HARDMTLS_PARAM_MAX_SIZE.to_bytes() {
                key.max_sig_size = unsafe { read_int_param(param) };
            }
        }

        i += 1;
    }
}

/// Read a c_int from an OSSL_PARAM.
///
/// # Safety
///
/// `param.data` must be a valid pointer to at least `size_of::<c_int>()` bytes.
#[allow(unsafe_code)]
unsafe fn read_int_param(param: &openssl_sys::OSSL_PARAM) -> c_int {
    unsafe { std::ptr::read(param.data.cast::<c_int>()) }
}

/// Write a c_int into an OSSL_PARAM and set return_size.
///
/// # Safety
///
/// `param.data` must be a valid pointer to at least `size_of::<c_int>()` bytes.
#[allow(unsafe_code)]
unsafe fn write_int_param(param: &mut openssl_sys::OSSL_PARAM, value: c_int) {
    unsafe { std::ptr::write(param.data.cast::<c_int>(), value) };
    param.return_size = std::mem::size_of::<c_int>();
}

/// Return a static empty (sentinel-only) OSSL_PARAM array.
fn empty_param_list() -> *const openssl_sys::OSSL_PARAM {
    struct SyncParams([openssl_sys::OSSL_PARAM; 1]);

    #[allow(unsafe_code)]
    unsafe impl Sync for SyncParams {}

    static EMPTY: SyncParams = SyncParams([openssl_sys::OSSL_PARAM {
        key: std::ptr::null(),
        data_type: 0,
        data: std::ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    }]);

    EMPTY.0.as_ptr()
}

// ═══════════════════════════════════════════════════════════════════════
// SIGNATURE dispatch functions
// ═══════════════════════════════════════════════════════════════════════

/// Allocate a new signing context.
#[allow(unsafe_code)]
extern "C" fn signature_newctx(_provctx: *mut c_void, _propq: *const c_char) -> *mut c_void {
    let ctx = Box::new(HardmtlsSignCtx {
        key: ptr::null(),
        tbs_buffer: Vec::new(),
    });
    Box::into_raw(ctx).cast::<c_void>()
}

/// Free a signing context.
#[allow(unsafe_code)]
extern "C" fn signature_freectx(ctx: *mut c_void) {
    if !ctx.is_null() {
        // SAFETY: ctx was allocated by Box::into_raw in signature_newctx.
        let _ = unsafe { Box::from_raw(ctx.cast::<HardmtlsSignCtx>()) };
    }
}

/// Duplicate a signing context.
#[allow(unsafe_code)]
extern "C" fn signature_dupctx(ctx: *mut c_void) -> *mut c_void {
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: ctx is our HardmtlsSignCtx.
    let src = unsafe { &*ctx.cast::<HardmtlsSignCtx>() };
    let dup = Box::new(HardmtlsSignCtx {
        key: src.key,
        tbs_buffer: src.tbs_buffer.clone(),
    });
    Box::into_raw(dup).cast::<c_void>()
}

/// Initialize a signing operation with the given key.
#[allow(unsafe_code)]
extern "C" fn signature_sign_init(
    ctx: *mut c_void,
    provkey: *mut c_void,
    _params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    if ctx.is_null() || provkey.is_null() {
        return 0;
    }
    // SAFETY: ctx is our HardmtlsSignCtx, provkey is our HardmtlsKey.
    let sign_ctx = unsafe { &mut *ctx.cast::<HardmtlsSignCtx>() };
    sign_ctx.key = provkey.cast::<HardmtlsKey>();
    1 // Success
}

/// Perform the actual signing operation.
///
/// If `sigret` is null, return the required signature buffer size in `siglen`.
/// Otherwise, compute the signature and write it to `sigret`.
#[allow(unsafe_code)]
extern "C" fn signature_sign(
    ctx: *mut c_void,
    sigret: *mut c_uchar,
    siglen: *mut usize,
    _sigsize: usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> c_int {
    if ctx.is_null() || siglen.is_null() {
        return 0;
    }

    // SAFETY: ctx is our HardmtlsSignCtx.
    let sign_ctx = unsafe { &*ctx.cast::<HardmtlsSignCtx>() };
    if sign_ctx.key.is_null() {
        log::error!("hardmTLS provider: sign called without key");
        return 0;
    }

    // SAFETY: key was set in sign_init.
    let key = unsafe { &*sign_ctx.key };
    let Some(sign_func) = key.sign_func else {
        log::error!("hardmTLS provider: sign called but sign_func not set");
        return 0;
    };

    if sigret.is_null() {
        // Size query — use max_sig_size from key metadata, fallback to 512.
        let size = if key.max_sig_size > 0 {
            key.max_sig_size as usize
        } else {
            512
        };
        // SAFETY: siglen is valid (checked above).
        unsafe { *siglen = size };
        return 1;
    }

    // Delegate to the sign callback.
    // SAFETY: sign_func, sigret, siglen, tbs are all valid pointers.
    let result = unsafe { sign_func(sigret, siglen, tbs, tbslen) };

    if result != 1 {
        log::error!("hardmTLS provider: sign_func returned failure");
        return 0;
    }

    1 // Success
}

/// Initialize a digest+sign operation.
///
/// OpenSSL uses this path during TLS handshakes. The `mdname` parameter
/// specifies the digest algorithm (e.g., "SHA256"), but our sign callback
/// handles all crypto internally (including hashing), so we ignore it.
#[allow(unsafe_code)]
extern "C" fn signature_digest_sign_init(
    ctx: *mut c_void,
    _mdname: *const c_char,
    provkey: *mut c_void,
    _params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    if ctx.is_null() || provkey.is_null() {
        return 0;
    }
    // SAFETY: ctx is our HardmtlsSignCtx, provkey is our HardmtlsKey.
    let sign_ctx = unsafe { &mut *ctx.cast::<HardmtlsSignCtx>() };
    sign_ctx.key = provkey.cast::<HardmtlsKey>();
    sign_ctx.tbs_buffer.clear();
    log::debug!("hardmTLS provider: digest_sign_init");
    1
}

/// Feed data into the digest+sign accumulator.
#[allow(unsafe_code)]
extern "C" fn signature_digest_sign_update(
    ctx: *mut c_void,
    data: *const c_uchar,
    datalen: usize,
) -> c_int {
    if ctx.is_null() || data.is_null() {
        return 0;
    }
    let sign_ctx = unsafe { &mut *ctx.cast::<HardmtlsSignCtx>() };
    // SAFETY: data/datalen are valid (OpenSSL contract).
    let slice = unsafe { std::slice::from_raw_parts(data, datalen) };
    sign_ctx.tbs_buffer.extend_from_slice(slice);
    1
}

/// Finalize digest+sign: pass all accumulated data to `sign_func`.
///
/// If `sigret` is null, return the required signature buffer size.
/// Otherwise, compute the signature.
#[allow(unsafe_code)]
extern "C" fn signature_digest_sign_final(
    ctx: *mut c_void,
    sigret: *mut c_uchar,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    if ctx.is_null() || siglen.is_null() {
        return 0;
    }

    let sign_ctx = unsafe { &*ctx.cast::<HardmtlsSignCtx>() };
    if sign_ctx.key.is_null() {
        log::error!("hardmTLS provider: digest_sign_final called without key");
        return 0;
    }

    let key = unsafe { &*sign_ctx.key };
    let Some(sign_func) = key.sign_func else {
        log::error!("hardmTLS provider: digest_sign_final but sign_func not set");
        return 0;
    };

    if sigret.is_null() {
        // Size query — use max_sig_size from metadata, fallback to 512.
        let size = if key.max_sig_size > 0 {
            key.max_sig_size as usize
        } else {
            512
        };
        unsafe { *siglen = size };
        return 1;
    }

    // Guard against buffer overflow.
    if sigsize < 512 {
        log::debug!("hardmTLS provider: sigsize={sigsize}, may be tight");
    }

    // Delegate to sign callback with all accumulated data.
    let tbs_ptr = sign_ctx.tbs_buffer.as_ptr();
    let tbs_len = sign_ctx.tbs_buffer.len();
    let result = unsafe { sign_func(sigret, siglen, tbs_ptr, tbs_len) };

    if result != 1 {
        log::error!("hardmTLS provider: sign_func returned failure in digest_sign_final");
        return 0;
    }

    1
}

/// One-shot digest+sign: sign all data in a single call.
#[allow(unsafe_code)]
extern "C" fn signature_digest_sign(
    ctx: *mut c_void,
    sigret: *mut c_uchar,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> c_int {
    if ctx.is_null() || siglen.is_null() {
        return 0;
    }

    let sign_ctx = unsafe { &*ctx.cast::<HardmtlsSignCtx>() };
    if sign_ctx.key.is_null() {
        log::error!("hardmTLS provider: digest_sign called without key");
        return 0;
    }

    let key = unsafe { &*sign_ctx.key };
    let Some(sign_func) = key.sign_func else {
        log::error!("hardmTLS provider: digest_sign but sign_func not set");
        return 0;
    };

    if sigret.is_null() {
        // Size query.
        let size = if key.max_sig_size > 0 {
            key.max_sig_size as usize
        } else {
            512
        };
        unsafe { *siglen = size };
        return 1;
    }

    if sigsize < 1 {
        log::error!("hardmTLS provider: digest_sign sigsize is 0");
        return 0;
    }

    // Delegate to sign callback directly (one-shot, no buffering).
    let result = unsafe { sign_func(sigret, siglen, tbs, tbslen) };

    if result != 1 {
        log::error!("hardmTLS provider: sign_func returned failure in digest_sign");
        return 0;
    }

    1
}

// ── Digest-verify stubs (sign-only proxy) ──────────────────────────────

/// Initialize digest+verify (stub — we are a sign-only proxy).
#[allow(unsafe_code)]
extern "C" fn signature_digest_verify_init(
    _ctx: *mut c_void,
    _mdname: *const c_char,
    _provkey: *mut c_void,
    _params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    log::debug!("hardmTLS provider: digest_verify_init called (sign-only proxy, returning 0)");
    0
}

/// Feed data into digest+verify (stub).
#[allow(unsafe_code)]
extern "C" fn signature_digest_verify_update(
    _ctx: *mut c_void,
    _data: *const c_uchar,
    _datalen: usize,
) -> c_int {
    0
}

/// Finalize digest+verify (stub).
#[allow(unsafe_code)]
extern "C" fn signature_digest_verify_final(
    _ctx: *mut c_void,
    _sig: *const c_uchar,
    _siglen: usize,
) -> c_int {
    0
}

/// One-shot digest+verify (stub).
#[allow(unsafe_code)]
extern "C" fn signature_digest_verify(
    _ctx: *mut c_void,
    _sig: *const c_uchar,
    _siglen: usize,
    _tbs: *const c_uchar,
    _tbslen: usize,
) -> c_int {
    0
}

// ── Signature context parameter functions ──────────────────────────────

/// Get signature context parameters (no-op).
#[allow(unsafe_code)]
extern "C" fn signature_get_ctx_params(
    _ctx: *mut c_void,
    _params: *mut openssl_sys::OSSL_PARAM,
) -> c_int {
    1
}

/// Declare gettable signature context parameters (empty).
#[allow(unsafe_code)]
extern "C" fn signature_gettable_ctx_params(
    _ctx: *const c_void,
    _provctx: *const c_void,
) -> *const openssl_sys::OSSL_PARAM {
    empty_param_list()
}

/// Set signature context parameters (accept and log, return success).
#[allow(unsafe_code)]
extern "C" fn signature_set_ctx_params(
    _ctx: *mut c_void,
    _params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    log::debug!("hardmTLS provider: set_ctx_params called (accepted)");
    1
}

/// Declare settable signature context parameters (empty).
#[allow(unsafe_code)]
extern "C" fn signature_settable_ctx_params(
    _ctx: *const c_void,
    _provctx: *const c_void,
) -> *const openssl_sys::OSSL_PARAM {
    empty_param_list()
}

// ── Signature MD context parameter functions ───────────────────────────

/// Get digest context parameters (no-op).
#[allow(unsafe_code)]
extern "C" fn signature_get_ctx_md_params(
    _ctx: *mut c_void,
    _params: *mut openssl_sys::OSSL_PARAM,
) -> c_int {
    1
}

/// Declare gettable digest context parameters (empty).
#[allow(unsafe_code)]
extern "C" fn signature_gettable_ctx_md_params(
    _ctx: *const c_void,
) -> *const openssl_sys::OSSL_PARAM {
    empty_param_list()
}

/// Set digest context parameters (no-op).
#[allow(unsafe_code)]
extern "C" fn signature_set_ctx_md_params(
    _ctx: *mut c_void,
    _params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    1
}

/// Declare settable digest context parameters (empty).
#[allow(unsafe_code)]
extern "C" fn signature_settable_ctx_md_params(
    _ctx: *const c_void,
) -> *const openssl_sys::OSSL_PARAM {
    empty_param_list()
}

// ═══════════════════════════════════════════════════════════════════════
// Dispatch tables
// ═══════════════════════════════════════════════════════════════════════

/// Helper macro to create a dispatch entry. This avoids repeating the
/// unsafe transmute boilerplate for every function.
macro_rules! dispatch_entry {
    ($id:expr, $func:expr, $sig:ty) => {
        OsslDispatch {
            function_id: $id,
            // SAFETY: We're transmuting from a concrete extern "C" fn type
            // to the generic `unsafe extern "C" fn()` that OsslDispatch stores.
            // OpenSSL will cast it back to the correct type based on function_id.
            function: Some(unsafe {
                std::mem::transmute::<$sig, unsafe extern "C" fn()>($func)
            }),
        }
    };
}

/// KEYMGMT dispatch table — 14 functions + sentinel.
#[allow(unsafe_code)]
static KEYMGMT_DISPATCH: [OsslDispatch; 15] = [
    dispatch_entry!(OSSL_FUNC_KEYMGMT_NEW, keymgmt_new,
        extern "C" fn(*mut c_void) -> *mut c_void),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_FREE, keymgmt_free,
        extern "C" fn(*mut c_void)),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_HAS, keymgmt_has,
        extern "C" fn(*const c_void, c_int) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_IMPORT, keymgmt_import,
        extern "C" fn(*mut c_void, c_int, *const openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, keymgmt_import_types,
        extern "C" fn(c_int) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_MATCH, keymgmt_match,
        extern "C" fn(*const c_void, *const c_void, c_int) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, keymgmt_get_params,
        extern "C" fn(*const c_void, *mut openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, keymgmt_gettable_params,
        extern "C" fn(*mut c_void) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_SET_PARAMS, keymgmt_set_params,
        extern "C" fn(*mut c_void, *const openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, keymgmt_settable_params,
        extern "C" fn(*mut c_void) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_VALIDATE, keymgmt_validate,
        extern "C" fn(*const c_void, c_int, c_int) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_EXPORT, keymgmt_export,
        extern "C" fn(*const c_void, c_int, Option<unsafe extern "C" fn(*const openssl_sys::OSSL_PARAM, *mut c_void) -> c_int>, *mut c_void) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, keymgmt_export_types,
        extern "C" fn(c_int) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_DUP, keymgmt_dup,
        extern "C" fn(*const c_void, c_int) -> *mut c_void),
    OsslDispatch::end(),
];

/// SIGNATURE dispatch table — 21 functions + sentinel.
#[allow(unsafe_code)]
static SIGNATURE_DISPATCH: [OsslDispatch; 22] = [
    dispatch_entry!(OSSL_FUNC_SIGNATURE_NEWCTX, signature_newctx,
        extern "C" fn(*mut c_void, *const c_char) -> *mut c_void),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_FREECTX, signature_freectx,
        extern "C" fn(*mut c_void)),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_DUPCTX, signature_dupctx,
        extern "C" fn(*mut c_void) -> *mut c_void),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_SIGN_INIT, signature_sign_init,
        extern "C" fn(*mut c_void, *mut c_void, *const openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_SIGN, signature_sign,
        extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize, *const c_uchar, usize) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, signature_digest_sign_init,
        extern "C" fn(*mut c_void, *const c_char, *mut c_void, *const openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, signature_digest_sign_update,
        extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, signature_digest_sign_final,
        extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_DIGEST_SIGN, signature_digest_sign,
        extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize, *const c_uchar, usize) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, signature_digest_verify_init,
        extern "C" fn(*mut c_void, *const c_char, *mut c_void, *const openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, signature_digest_verify_update,
        extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, signature_digest_verify_final,
        extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, signature_digest_verify,
        extern "C" fn(*mut c_void, *const c_uchar, usize, *const c_uchar, usize) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, signature_get_ctx_params,
        extern "C" fn(*mut c_void, *mut openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, signature_gettable_ctx_params,
        extern "C" fn(*const c_void, *const c_void) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, signature_set_ctx_params,
        extern "C" fn(*mut c_void, *const openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, signature_settable_ctx_params,
        extern "C" fn(*const c_void, *const c_void) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, signature_get_ctx_md_params,
        extern "C" fn(*mut c_void, *mut openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, signature_gettable_ctx_md_params,
        extern "C" fn(*const c_void) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, signature_set_ctx_md_params,
        extern "C" fn(*mut c_void, *const openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, signature_settable_ctx_md_params,
        extern "C" fn(*const c_void) -> *const openssl_sys::OSSL_PARAM),
    OsslDispatch::end(),
];

// ═══════════════════════════════════════════════════════════════════════
// Algorithm tables
// ═══════════════════════════════════════════════════════════════════════

/// KEYMGMT algorithm table — registers RSA and EC key types.
static KEYMGMT_ALGORITHMS: [OsslAlgorithm; 3] = [
    OsslAlgorithm {
        algorithm_names: RSA_ALG_NAME.as_ptr(),
        property_definition: PROVIDER_PROPS.as_ptr(),
        implementation: KEYMGMT_DISPATCH.as_ptr(),
        algorithm_description: c"hardmTLS RSA key".as_ptr(),
    },
    OsslAlgorithm {
        algorithm_names: EC_ALG_NAME.as_ptr(),
        property_definition: PROVIDER_PROPS.as_ptr(),
        implementation: KEYMGMT_DISPATCH.as_ptr(),
        algorithm_description: c"hardmTLS EC key".as_ptr(),
    },
    OsslAlgorithm::end(),
];

/// SIGNATURE algorithm table — registers RSA and EC signatures.
static SIGNATURE_ALGORITHMS: [OsslAlgorithm; 3] = [
    OsslAlgorithm {
        algorithm_names: RSA_ALG_NAME.as_ptr(),
        property_definition: PROVIDER_PROPS.as_ptr(),
        implementation: SIGNATURE_DISPATCH.as_ptr(),
        algorithm_description: c"hardmTLS RSA signature".as_ptr(),
    },
    OsslAlgorithm {
        algorithm_names: EC_ALG_NAME.as_ptr(),
        property_definition: PROVIDER_PROPS.as_ptr(),
        implementation: SIGNATURE_DISPATCH.as_ptr(),
        algorithm_description: c"hardmTLS EC signature".as_ptr(),
    },
    OsslAlgorithm::end(),
];

// ═══════════════════════════════════════════════════════════════════════
// Provider init
// ═══════════════════════════════════════════════════════════════════════

/// Query callback — OpenSSL calls this to discover our algorithms.
#[allow(unsafe_code)]
extern "C" fn provider_query_operation(
    _provctx: *mut c_void,
    operation_id: c_int,
    _no_cache: *mut c_int,
) -> *const OsslAlgorithm {
    match operation_id {
        x if x == OSSL_OP_KEYMGMT => KEYMGMT_ALGORITHMS.as_ptr(),
        x if x == OSSL_OP_SIGNATURE => SIGNATURE_ALGORITHMS.as_ptr(),
        _ => ptr::null(),
    }
}

/// Provider teardown (no-op for now).
#[allow(unsafe_code)]
extern "C" fn provider_teardown(_provctx: *mut c_void) {
    log::debug!("hardmTLS provider: teardown");
}

/// Function ID for `query_operation` in the provider dispatch table.
const OSSL_FUNC_PROVIDER_QUERY_OPERATION: c_int = 1027;
/// Function ID for `teardown` in the provider dispatch table.
const OSSL_FUNC_PROVIDER_TEARDOWN: c_int = 1024;

/// Provider-level dispatch table (returned from `OSSL_provider_init`).
#[allow(unsafe_code)]
static PROVIDER_DISPATCH: [OsslDispatch; 3] = [
    dispatch_entry!(OSSL_FUNC_PROVIDER_TEARDOWN, provider_teardown,
        extern "C" fn(*mut c_void)),
    dispatch_entry!(OSSL_FUNC_PROVIDER_QUERY_OPERATION, provider_query_operation,
        extern "C" fn(*mut c_void, c_int, *mut c_int) -> *const OsslAlgorithm),
    OsslDispatch::end(),
];

/// Provider init entry point — called by OpenSSL when the provider is loaded.
///
/// # Safety
///
/// Called by OpenSSL via `OSSL_PROVIDER_load`. All pointers are managed by OpenSSL.
#[allow(unsafe_code)]
unsafe extern "C" fn hardmtls_provider_init(
    _handle: *const c_void,
    _in_dispatch: *const OsslDispatch,
    out_dispatch: *mut *const OsslDispatch,
    out_provctx: *mut *mut c_void,
) -> c_int {
    // SAFETY: out_dispatch and out_provctx are valid (from OpenSSL).
    unsafe {
        *out_dispatch = PROVIDER_DISPATCH.as_ptr();
        *out_provctx = ptr::null_mut(); // We don't need provider-level context.
    }
    log::debug!("hardmTLS provider: initialized");
    1 // Success
}

// ═══════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════

/// Register the hardmTLS provider as a built-in OpenSSL provider.
///
/// This must be called before any `EVP_PKEY` operations that use our provider.
/// It is safe to call multiple times (uses `Once`).
///
/// # Errors
///
/// Returns an error if `OSSL_PROVIDER_add_builtin` fails.
#[allow(unsafe_code)]
pub fn register_provider() -> Result<(), crate::error::HardmtlsError> {
    let mut result = Ok(());

    PROVIDER_INIT.call_once(|| {
        // SAFETY: PROVIDER_NAME is null-terminated, hardmtls_provider_init has correct signature.
        let rc = unsafe {
            OSSL_PROVIDER_add_builtin(
                ptr::null_mut(), // default library context
                PROVIDER_NAME.as_ptr(),
                hardmtls_provider_init,
            )
        };
        if rc != 1 {
            result = Err(crate::error::HardmtlsError::SslError(
                "OSSL_PROVIDER_add_builtin failed".into(),
            ));
            return;
        }

        // Now load it to activate.
        // SAFETY: FFI call with valid name.
        let prov =
            unsafe { openssl_sys::OSSL_PROVIDER_load(ptr::null_mut(), PROVIDER_NAME.as_ptr()) };
        if prov.is_null() {
            result = Err(crate::error::HardmtlsError::SslError(
                "OSSL_PROVIDER_load failed for hardmtls".into(),
            ));
            return;
        }

        // Also load the default provider. When any provider is explicitly loaded,
        // OpenSSL stops auto-loading the default provider. Without this, standard
        // algorithms (ciphers, digests, RSA, etc.) become unavailable, breaking
        // SSL_CTX_new and normal TLS operations.
        let default_prov =
            unsafe { openssl_sys::OSSL_PROVIDER_load(ptr::null_mut(), c"default".as_ptr()) };
        if default_prov.is_null() {
            result = Err(crate::error::HardmtlsError::SslError(
                "OSSL_PROVIDER_load failed for default provider".into(),
            ));
            return;
        }

        log::info!("hardmTLS: OpenSSL provider registered and loaded (with default)");
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_tables_are_well_formed() {
        // KEYMGMT has 14 entries + sentinel.
        assert_eq!(KEYMGMT_DISPATCH.len(), 15);
        assert_eq!(KEYMGMT_DISPATCH[14].function_id, 0);

        // SIGNATURE has 21 entries + sentinel.
        assert_eq!(SIGNATURE_DISPATCH.len(), 22);
        assert_eq!(SIGNATURE_DISPATCH[21].function_id, 0);

        // Provider dispatch has 2 entries + sentinel.
        assert_eq!(PROVIDER_DISPATCH.len(), 3);
        assert_eq!(PROVIDER_DISPATCH[2].function_id, 0);
    }

    #[test]
    fn algorithm_tables_are_well_formed() {
        assert_eq!(KEYMGMT_ALGORITHMS.len(), 3);
        assert!(KEYMGMT_ALGORITHMS[2].algorithm_names.is_null());

        assert_eq!(SIGNATURE_ALGORITHMS.len(), 3);
        assert!(SIGNATURE_ALGORITHMS[2].algorithm_names.is_null());
    }

    #[test]
    fn provider_name_is_valid_cstr() {
        // CStr literals are always null-terminated.
        assert_eq!(PROVIDER_NAME.to_bytes(), b"hardmtls");
    }

    #[test]
    fn register_provider_succeeds() {
        // This test actually registers the hardmTLS provider with OpenSSL.
        // It verifies that OSSL_PROVIDER_add_builtin + OSSL_PROVIDER_load work.
        let result = register_provider();
        assert!(result.is_ok(), "register_provider failed: {result:?}");
    }

    #[test]
    fn register_provider_idempotent() {
        // Calling register_provider multiple times should be safe (uses Once).
        let _ = register_provider();
        let result = register_provider();
        assert!(result.is_ok());
    }
}
