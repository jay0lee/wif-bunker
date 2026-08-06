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
//!   │     new/free/has/import/match
//!   └── SIGNATURE "RSA" + "EC"
//!         newctx/freectx/sign_init/sign
//! ```

use std::ffi::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use std::sync::Once;

use crate::provider_ffi::{
    OSSL_PROVIDER_add_builtin, OsslAlgorithm, OsslDispatch, OSSL_FUNC_KEYMGMT_FREE,
    OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
    OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
    OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_SIGN,
    OSSL_FUNC_SIGNATURE_SIGN_INIT, OSSL_OP_KEYMGMT, OSSL_OP_SIGNATURE,
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
/// `SignForPython` wrapper.
struct HardmtlsKey {
    /// The signing callback provided by the caller.
    /// `None` after `keymgmt_new`, populated by `keymgmt_import`.
    sign_func: Option<SignCallback>,
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
    let key = Box::new(HardmtlsKey { sign_func: None });
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
/// When called with our `"hardmtls-sign-func"` parameter, stores the signing
/// callback. When called without it (e.g., during cross-provider key
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

    // SAFETY: params is valid and null-terminated (OpenSSL contract).
    let sign_func = unsafe { extract_sign_func_from_params(params) };

    if let Some(func) = sign_func {
        // SAFETY: keydata is valid (from keymgmt_new), we have exclusive access.
        let key = unsafe { &mut *keydata.cast::<HardmtlsKey>() };
        key.sign_func = Some(func);
        log::debug!("hardmTLS provider: imported sign_func into key");
    } else {
        // No sign_func — this is a comparison import (OpenSSL importing
        // a cert's public key into our keymgmt for matching). That's fine.
        log::debug!("hardmTLS provider: import without sign_func (comparison key)");
    }

    1 // Always succeed
}

/// Declare the types of parameters that `keymgmt_import` accepts.
///
/// OpenSSL requires this whenever `keymgmt_import` is provided (the import
/// function count must be exactly 2: `import` + `import_types`).
#[allow(unsafe_code)]
extern "C" fn keymgmt_import_types(_selection: c_int) -> *const openssl_sys::OSSL_PARAM {
    use crate::provider_ffi::{HARDMTLS_PARAM_SIGN_FUNC, OSSL_PARAM_OCTET_STRING};

    /// Wrapper to allow `OSSL_PARAM` array in a static.
    struct SyncParams([openssl_sys::OSSL_PARAM; 2]);

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
        // Size query — return a generous maximum.
        // RSA-4096 = 512 bytes, ECDSA P-384 ≈ 104 bytes.
        // SAFETY: siglen is valid (checked above).
        unsafe { *siglen = 512 };
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
        // Size query.
        unsafe { *siglen = 512 };
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

// ═══════════════════════════════════════════════════════════════════════
// Dispatch tables
// ═══════════════════════════════════════════════════════════════════════

/// KEYMGMT dispatch table.
#[allow(unsafe_code)]
static KEYMGMT_DISPATCH: [OsslDispatch; 7] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: Some(unsafe {
            std::mem::transmute::<extern "C" fn(*mut c_void) -> *mut c_void, unsafe extern "C" fn()>(
                keymgmt_new,
            )
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: Some(unsafe {
            std::mem::transmute::<extern "C" fn(*mut c_void), unsafe extern "C" fn()>(keymgmt_free)
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: Some(unsafe {
            std::mem::transmute::<
                extern "C" fn(*const c_void, c_int) -> c_int,
                unsafe extern "C" fn(),
            >(keymgmt_has)
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT,
        function: Some(unsafe {
            std::mem::transmute::<
                extern "C" fn(*mut c_void, c_int, *const openssl_sys::OSSL_PARAM) -> c_int,
                unsafe extern "C" fn(),
            >(keymgmt_import)
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        function: Some(unsafe {
            std::mem::transmute::<
                extern "C" fn(c_int) -> *const openssl_sys::OSSL_PARAM,
                unsafe extern "C" fn(),
            >(keymgmt_import_types)
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_MATCH,
        function: Some(unsafe {
            std::mem::transmute::<
                extern "C" fn(*const c_void, *const c_void, c_int) -> c_int,
                unsafe extern "C" fn(),
            >(keymgmt_match)
        }),
    },
    OsslDispatch::end(),
];

/// SIGNATURE dispatch table.
#[allow(unsafe_code)]
static SIGNATURE_DISPATCH: [OsslDispatch; 8] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: Some(unsafe {
            std::mem::transmute::<
                extern "C" fn(*mut c_void, *const c_char) -> *mut c_void,
                unsafe extern "C" fn(),
            >(signature_newctx)
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: Some(unsafe {
            std::mem::transmute::<extern "C" fn(*mut c_void), unsafe extern "C" fn()>(
                signature_freectx,
            )
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: Some(unsafe {
            std::mem::transmute::<
                extern "C" fn(*mut c_void, *mut c_void, *const openssl_sys::OSSL_PARAM) -> c_int,
                unsafe extern "C" fn(),
            >(signature_sign_init)
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN,
        function: Some(unsafe {
            std::mem::transmute::<
                extern "C" fn(
                    *mut c_void,
                    *mut c_uchar,
                    *mut usize,
                    usize,
                    *const c_uchar,
                    usize,
                ) -> c_int,
                unsafe extern "C" fn(),
            >(signature_sign)
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: Some(unsafe {
            std::mem::transmute::<
                extern "C" fn(
                    *mut c_void,
                    *const c_char,
                    *mut c_void,
                    *const openssl_sys::OSSL_PARAM,
                ) -> c_int,
                unsafe extern "C" fn(),
            >(signature_digest_sign_init)
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: Some(unsafe {
            std::mem::transmute::<
                extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int,
                unsafe extern "C" fn(),
            >(signature_digest_sign_update)
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: Some(unsafe {
            std::mem::transmute::<
                extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize) -> c_int,
                unsafe extern "C" fn(),
            >(signature_digest_sign_final)
        }),
    },
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
    OsslDispatch {
        function_id: OSSL_FUNC_PROVIDER_TEARDOWN,
        function: Some(unsafe {
            std::mem::transmute::<extern "C" fn(*mut c_void), unsafe extern "C" fn()>(
                provider_teardown,
            )
        }),
    },
    OsslDispatch {
        function_id: OSSL_FUNC_PROVIDER_QUERY_OPERATION,
        function: Some(unsafe {
            std::mem::transmute::<
                extern "C" fn(*mut c_void, c_int, *mut c_int) -> *const OsslAlgorithm,
                unsafe extern "C" fn(),
            >(provider_query_operation)
        }),
    },
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
        // KEYMGMT has 6 entries + sentinel.
        assert_eq!(KEYMGMT_DISPATCH.len(), 7);
        assert_eq!(KEYMGMT_DISPATCH[6].function_id, 0);

        // SIGNATURE has 7 entries + sentinel.
        assert_eq!(SIGNATURE_DISPATCH.len(), 8);
        assert_eq!(SIGNATURE_DISPATCH[7].function_id, 0);

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
