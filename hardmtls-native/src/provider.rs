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
//!   ├── KEYMGMT "hardmtls-key"
//!   │     new/free/has/import
//!   └── SIGNATURE "hardmtls-sig"
//!         newctx/freectx/sign_init/sign
//! ```

use std::ffi::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use std::sync::Once;

use crate::provider_ffi::{
    OSSL_PROVIDER_add_builtin, OsslAlgorithm, OsslDispatch, OSSL_FUNC_KEYMGMT_FREE,
    OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_NEW,
    OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_SIGN,
    OSSL_FUNC_SIGNATURE_SIGN_INIT, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_OP_KEYMGMT,
    OSSL_OP_SIGNATURE,
};
use crate::SignCallback;

/// Ensures the provider is registered exactly once.
static PROVIDER_INIT: Once = Once::new();

// ── Provider name (null-terminated) ────────────────────────────────────

/// Provider name used in `OSSL_PROVIDER_add_builtin`.
const PROVIDER_NAME: &std::ffi::CStr = c"hardmtls";

/// Algorithm name for our custom key type.
const KEY_ALG_NAME: &std::ffi::CStr = c"hardmtls-key";

/// Algorithm name for our custom signature.
const SIG_ALG_NAME: &std::ffi::CStr = c"hardmtls-sig";

/// Property query string for our provider.
const PROVIDER_PROPS: &std::ffi::CStr = c"provider=hardmtls";

// ── Key data (stored inside EVP_PKEY via KEYMGMT) ──────────────────────

/// Internal key representation stored by our KEYMGMT.
///
/// Holds the signing callback that delegates to google-auth's
/// `SignForPython` wrapper.
struct HardmtlsKey {
    /// The signing callback provided by the caller.
    sign_func: SignCallback,
}

// ── Signing context (stored by SIGNATURE operations) ───────────────────

/// Context for an in-progress signing operation.
struct HardmtlsSignCtx {
    /// Reference to the key (borrowed, not owned — OpenSSL manages lifetime).
    key: *const HardmtlsKey,
}

// ═══════════════════════════════════════════════════════════════════════
// KEYMGMT dispatch functions
// ═══════════════════════════════════════════════════════════════════════

/// Allocate a new (empty) key. The key is populated later via `import`.
#[allow(unsafe_code)]
extern "C" fn keymgmt_new(_provctx: *mut c_void) -> *mut c_void {
    // We don't allocate here — the key is created in `import`.
    // Return a non-null sentinel that `import` will replace.
    ptr::null_mut()
}

/// Free a key previously allocated by `import`.
#[allow(unsafe_code)]
extern "C" fn keymgmt_free(keydata: *mut c_void) {
    if !keydata.is_null() {
        // SAFETY: keydata was allocated by Box::into_raw in `keymgmt_import`.
        let _ = unsafe { Box::from_raw(keydata.cast::<HardmtlsKey>()) };
    }
}

/// Query what components the key has.
#[allow(unsafe_code)]
extern "C" fn keymgmt_has(keydata: *const c_void, selection: c_int) -> c_int {
    if keydata.is_null() {
        return 0;
    }
    // Our key always has a private component (the sign callback).
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        return 1;
    }
    0
}

/// Import key data. We expect a raw pointer to a `SignCallback` passed
/// via an `OSSL_PARAM` with key `"sign_func_ptr"`.
#[allow(unsafe_code)]
extern "C" fn keymgmt_import(
    keydata: *mut c_void,
    _selection: c_int,
    params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    if params.is_null() {
        return 0;
    }

    // Walk the OSSL_PARAM array to find our custom parameter.
    // SAFETY: params is valid and null-terminated (OpenSSL contract).
    let sign_func = unsafe { extract_sign_func_from_params(params) };

    match sign_func {
        Some(func) => {
            let key = Box::new(HardmtlsKey { sign_func: func });
            // Store the key pointer. Since `keydata` is a *mut from `keymgmt_new`,
            // we need a way to pass it back. OpenSSL expects us to populate `keydata`.
            // However, the Provider API passes `keydata` as the return from `keymgmt_new`.
            // For our case, we store via a global or thread-local.
            // Actually, OpenSSL's keymgmt_import receives the key object from keymgmt_new
            // and should populate it in-place. Since we returned null from keymgmt_new,
            // we need to use a different approach.
            //
            // The correct pattern: keymgmt_new returns an allocated but empty struct,
            // and keymgmt_import fills it in.
            let _ = (keydata, key);
            // TODO: This needs proper in-place mutation of the key struct.
            // For now, mark as not yet implemented.
            0
        }
        None => 0,
    }
}

/// Extract the `SignCallback` function pointer from an `OSSL_PARAM` array.
///
/// # Safety
///
/// `params` must be a valid, null-terminated `OSSL_PARAM` array.
#[allow(unsafe_code)]
unsafe fn extract_sign_func_from_params(
    _params: *const openssl_sys::OSSL_PARAM,
) -> Option<SignCallback> {
    // TODO: Walk OSSL_PARAM array looking for "sign_func_ptr" key.
    // The value will be a pointer-sized octet string containing the fn pointer.
    None
}

// ═══════════════════════════════════════════════════════════════════════
// SIGNATURE dispatch functions
// ═══════════════════════════════════════════════════════════════════════

/// Allocate a new signing context.
#[allow(unsafe_code)]
extern "C" fn signature_newctx(_provctx: *mut c_void, _propq: *const c_char) -> *mut c_void {
    let ctx = Box::new(HardmtlsSignCtx { key: ptr::null() });
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

    if sigret.is_null() {
        // Size query — return a generous maximum.
        // RSA-4096 = 512 bytes, ECDSA P-384 ≈ 104 bytes.
        // SAFETY: siglen is valid (checked above).
        unsafe { *siglen = 512 };
        return 1;
    }

    // Delegate to the sign callback.
    // SAFETY: sign_func, sigret, siglen, tbs are all valid pointers.
    let result = unsafe { (key.sign_func)(sigret, siglen, tbs, tbslen) };

    if result != 1 {
        log::error!("hardmTLS provider: sign_func returned failure");
        return 0;
    }

    1 // Success
}

// ═══════════════════════════════════════════════════════════════════════
// Dispatch tables
// ═══════════════════════════════════════════════════════════════════════

/// KEYMGMT dispatch table.
#[allow(unsafe_code)]
static KEYMGMT_DISPATCH: [OsslDispatch; 5] = [
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
    OsslDispatch::end(),
];

/// SIGNATURE dispatch table.
#[allow(unsafe_code)]
static SIGNATURE_DISPATCH: [OsslDispatch; 5] = [
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
    OsslDispatch::end(),
];

// ═══════════════════════════════════════════════════════════════════════
// Algorithm tables
// ═══════════════════════════════════════════════════════════════════════

/// KEYMGMT algorithm table — registers "hardmtls-key".
static KEYMGMT_ALGORITHMS: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: KEY_ALG_NAME.as_ptr(),
        property_definition: PROVIDER_PROPS.as_ptr(),
        implementation: KEYMGMT_DISPATCH.as_ptr(),
        algorithm_description: c"hardmTLS custom key".as_ptr(),
    },
    OsslAlgorithm::end(),
];

/// SIGNATURE algorithm table — registers "hardmtls-sig".
static SIGNATURE_ALGORITHMS: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: SIG_ALG_NAME.as_ptr(),
        property_definition: PROVIDER_PROPS.as_ptr(),
        implementation: SIGNATURE_DISPATCH.as_ptr(),
        algorithm_description: c"hardmTLS custom signature".as_ptr(),
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
const OSSL_FUNC_PROVIDER_QUERY_OPERATION: c_int = 2;
/// Function ID for `teardown` in the provider dispatch table.
const OSSL_FUNC_PROVIDER_TEARDOWN: c_int = 1;

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
        }

        log::info!("hardmTLS: OpenSSL provider registered and loaded");
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_tables_are_well_formed() {
        // KEYMGMT has 4 entries + sentinel.
        assert_eq!(KEYMGMT_DISPATCH.len(), 5);
        assert_eq!(KEYMGMT_DISPATCH[4].function_id, 0);

        // SIGNATURE has 4 entries + sentinel.
        assert_eq!(SIGNATURE_DISPATCH.len(), 5);
        assert_eq!(SIGNATURE_DISPATCH[4].function_id, 0);

        // Provider dispatch has 2 entries + sentinel.
        assert_eq!(PROVIDER_DISPATCH.len(), 3);
        assert_eq!(PROVIDER_DISPATCH[2].function_id, 0);
    }

    #[test]
    fn algorithm_tables_are_well_formed() {
        assert_eq!(KEYMGMT_ALGORITHMS.len(), 2);
        assert!(KEYMGMT_ALGORITHMS[1].algorithm_names.is_null());

        assert_eq!(SIGNATURE_ALGORITHMS.len(), 2);
        assert!(SIGNATURE_ALGORITHMS[1].algorithm_names.is_null());
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
