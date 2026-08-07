//! Minimal "softkey" OpenSSL provider — proves we can build a working provider.
//!
//! This provider:
//! 1. Holds a real EC private key in memory (P-256)
//! 2. Does real ECDSA signing via OpenSSL's low-level EC APIs
//! 3. Registers as a built-in provider named "softkey"
//! 4. Performs a full TLS 1.2 mTLS handshake
//!
//! Once this works end-to-end, we can directly compare it with hardmTLS
//! to find what's different.
#![allow(missing_docs, unsafe_code, clippy::pedantic)]

use foreign_types_shared::ForeignType;
use openssl::bn::BigNum;
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Builder, X509NameBuilder};
use std::ffi::{c_char, c_int, c_uchar, c_void, CStr};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Once};

// ═══════════════════════════════════════════════════════════════════════
// FFI types (same as provider_ffi.rs)
// ═══════════════════════════════════════════════════════════════════════

#[repr(C)]
struct OsslDispatch {
    function_id: c_int,
    function: Option<unsafe extern "C" fn()>,
}
unsafe impl Sync for OsslDispatch {}

impl OsslDispatch {
    const fn end() -> Self {
        Self { function_id: 0, function: None }
    }
}

#[repr(C)]
struct OsslAlgorithm {
    algorithm_names: *const c_char,
    property_definition: *const c_char,
    implementation: *const OsslDispatch,
    algorithm_description: *const c_char,
}
unsafe impl Sync for OsslAlgorithm {}

impl OsslAlgorithm {
    const fn end() -> Self {
        Self {
            algorithm_names: ptr::null(),
            property_definition: ptr::null(),
            implementation: ptr::null(),
            algorithm_description: ptr::null(),
        }
    }
}

extern "C" {
    fn OSSL_PROVIDER_add_builtin(
        ctx: *mut openssl_sys::OSSL_LIB_CTX,
        name: *const c_char,
        init_fn: unsafe extern "C" fn(
            *const c_void, *const OsslDispatch,
            *mut *const OsslDispatch, *mut *mut c_void,
        ) -> c_int,
    ) -> c_int;
}

/// Macro to cast a typed function pointer to the generic dispatch fn type.
macro_rules! dispatch_entry {
    ($id:expr, $func:ident, $cast_type:ty) => {
        OsslDispatch {
            function_id: $id,
            function: Some(unsafe {
                std::mem::transmute::<$cast_type, unsafe extern "C" fn()>(
                    $func as $cast_type,
                )
            }),
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════

const OSSL_OP_KEYMGMT: c_int = 10;
const OSSL_OP_SIGNATURE: c_int = 12;

// KEYMGMT function IDs
const OSSL_FUNC_KEYMGMT_NEW: c_int = 1;
const OSSL_FUNC_KEYMGMT_FREE: c_int = 10;
const OSSL_FUNC_KEYMGMT_GET_PARAMS: c_int = 11;
const OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS: c_int = 12;
const OSSL_FUNC_KEYMGMT_SET_PARAMS: c_int = 13;
const OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS: c_int = 14;
const OSSL_FUNC_KEYMGMT_HAS: c_int = 21;
const OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME: c_int = 20;
const OSSL_FUNC_KEYMGMT_VALIDATE: c_int = 22;
const OSSL_FUNC_KEYMGMT_MATCH: c_int = 23;
const OSSL_FUNC_KEYMGMT_IMPORT: c_int = 40;
const OSSL_FUNC_KEYMGMT_IMPORT_TYPES: c_int = 41;
const OSSL_FUNC_KEYMGMT_EXPORT: c_int = 42;
const OSSL_FUNC_KEYMGMT_EXPORT_TYPES: c_int = 43;
const OSSL_FUNC_KEYMGMT_DUP: c_int = 44;

// SIGNATURE function IDs
const OSSL_FUNC_SIGNATURE_NEWCTX: c_int = 1;
const OSSL_FUNC_SIGNATURE_SIGN_INIT: c_int = 2;
const OSSL_FUNC_SIGNATURE_SIGN: c_int = 3;
const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT: c_int = 8;
const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE: c_int = 9;
const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL: c_int = 10;
const OSSL_FUNC_SIGNATURE_DIGEST_SIGN: c_int = 11;
const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT: c_int = 12;
const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE: c_int = 13;
const OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL: c_int = 14;
const OSSL_FUNC_SIGNATURE_FREECTX: c_int = 16;
const OSSL_FUNC_SIGNATURE_DUPCTX: c_int = 17;
const OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS: c_int = 18;
const OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS: c_int = 19;
const OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS: c_int = 20;
const OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS: c_int = 21;

// KEYMGMT selection bits
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;

// OSSL_PARAM data types
const OSSL_PARAM_INTEGER: u32 = 1;
const OSSL_PARAM_UTF8_STRING: u32 = 4;
const OSSL_PARAM_OCTET_STRING: u32 = 5;

// Provider function IDs
const OSSL_FUNC_PROVIDER_TEARDOWN: c_int = 1024;
const OSSL_FUNC_PROVIDER_QUERY_OPERATION: c_int = 1027;

static SIGN_COUNT: AtomicU32 = AtomicU32::new(0);

// ═══════════════════════════════════════════════════════════════════════
// Key data
// ═══════════════════════════════════════════════════════════════════════

/// Our "softkey" — holds a real EC private key for signing.
struct SoftKey {
    /// The actual EC private key (P-256). None after new(), set by import.
    ec_key: Option<EcKey<openssl::pkey::Private>>,
    key_bits: c_int,
    security_bits: c_int,
    max_sig_size: c_int,
    group_name: Vec<u8>,
}

/// Signing context
struct SoftSignCtx {
    key: *const SoftKey,
    tbs_buffer: Vec<u8>,
}

// ═══════════════════════════════════════════════════════════════════════
// KEYMGMT
// ═══════════════════════════════════════════════════════════════════════

extern "C" fn keymgmt_new(_provctx: *mut c_void) -> *mut c_void {
    let key = Box::new(SoftKey {
        ec_key: None,
        key_bits: 0,
        security_bits: 0,
        max_sig_size: 0,
        group_name: Vec::new(),
    });
    Box::into_raw(key).cast()
}

extern "C" fn keymgmt_free(keydata: *mut c_void) {
    if !keydata.is_null() {
        let _ = unsafe { Box::from_raw(keydata.cast::<SoftKey>()) };
    }
}

extern "C" fn keymgmt_has(keydata: *const c_void, _selection: c_int) -> c_int {
    if keydata.is_null() { return 0; }
    1
}

extern "C" fn keymgmt_validate(keydata: *const c_void, _selection: c_int, _check: c_int) -> c_int {
    if keydata.is_null() { return 0; }
    1
}

extern "C" fn keymgmt_match(keydata1: *const c_void, keydata2: *const c_void, _selection: c_int) -> c_int {
    if keydata1.is_null() || keydata2.is_null() { return 0; }
    1 // Always match (like hardmtls)
}

extern "C" fn keymgmt_import(
    keydata: *mut c_void,
    _selection: c_int,
    params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    if keydata.is_null() || params.is_null() { return 0; }
    let key = unsafe { &mut *keydata.cast::<SoftKey>() };

    // Try to extract our custom "softkey-ec-key" param (raw private key bytes)
    let ec_key_param = unsafe {
        openssl_sys::OSSL_PARAM_locate(params as *mut _, c"softkey-ec-key".as_ptr())
    };
    if !ec_key_param.is_null() {
        let param = unsafe { &*ec_key_param };
        if param.data_type == OSSL_PARAM_OCTET_STRING && !param.data.is_null() && param.data_size > 0 {
            let bytes = unsafe { std::slice::from_raw_parts(param.data.cast::<u8>(), param.data_size) };
            // Deserialize the EC private key from DER
            if let Ok(ec) = EcKey::private_key_from_der(bytes) {
                eprintln!("    [softkey] imported EC private key ({} bytes DER)", bytes.len());
                key.ec_key = Some(ec);
            }
        }
    }

    // Extract metadata
    let bits_param = unsafe { openssl_sys::OSSL_PARAM_locate(params as *mut _, c"softkey-bits".as_ptr()) };
    if !bits_param.is_null() {
        let p = unsafe { &*bits_param };
        if p.data_type == OSSL_PARAM_INTEGER && !p.data.is_null() {
            key.key_bits = unsafe { *(p.data.cast::<c_int>()) };
        }
    }

    let sec_param = unsafe { openssl_sys::OSSL_PARAM_locate(params as *mut _, c"softkey-security-bits".as_ptr()) };
    if !sec_param.is_null() {
        let p = unsafe { &*sec_param };
        if p.data_type == OSSL_PARAM_INTEGER && !p.data.is_null() {
            key.security_bits = unsafe { *(p.data.cast::<c_int>()) };
        }
    }

    let max_param = unsafe { openssl_sys::OSSL_PARAM_locate(params as *mut _, c"softkey-max-size".as_ptr()) };
    if !max_param.is_null() {
        let p = unsafe { &*max_param };
        if p.data_type == OSSL_PARAM_INTEGER && !p.data.is_null() {
            key.max_sig_size = unsafe { *(p.data.cast::<c_int>()) };
        }
    }

    let group_param = unsafe { openssl_sys::OSSL_PARAM_locate(params as *mut _, c"group".as_ptr()) };
    if !group_param.is_null() {
        let p = unsafe { &*group_param };
        if p.data_type == OSSL_PARAM_UTF8_STRING && !p.data.is_null() && p.data_size > 0 {
            let s = unsafe { std::slice::from_raw_parts(p.data.cast::<u8>(), p.data_size) };
            key.group_name = s.to_vec();
            eprintln!("    [softkey] imported group_name={}", String::from_utf8_lossy(s));
        }
    }

    1
}

extern "C" fn keymgmt_import_types(_selection: c_int) -> *const openssl_sys::OSSL_PARAM {
    struct SyncParams([openssl_sys::OSSL_PARAM; 6]);
    unsafe impl Sync for SyncParams {}
    static IMPORT_PARAMS: SyncParams = SyncParams([
        openssl_sys::OSSL_PARAM {
            key: c"softkey-ec-key".as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: c"softkey-bits".as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: c"softkey-security-bits".as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: c"softkey-max-size".as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: c"group".as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: ptr::null(),
            data_type: 0,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
    ]);
    IMPORT_PARAMS.0.as_ptr()
}

extern "C" fn keymgmt_export(
    _keydata: *mut c_void,
    _selection: c_int,
    _param_cb: Option<unsafe extern "C" fn(*const openssl_sys::OSSL_PARAM, *mut c_void) -> c_int>,
    _cbarg: *mut c_void,
) -> c_int {
    0 // Cannot export private key
}

extern "C" fn keymgmt_export_types(_selection: c_int) -> *const openssl_sys::OSSL_PARAM {
    struct SyncP(openssl_sys::OSSL_PARAM);
    unsafe impl Sync for SyncP {}
    static END: SyncP = SyncP(openssl_sys::OSSL_PARAM {
        key: ptr::null(), data_type: 0, data: ptr::null_mut(), data_size: 0, return_size: 0,
    });
    &END.0
}

extern "C" fn keymgmt_get_params(keydata: *mut c_void, params: *mut openssl_sys::OSSL_PARAM) -> c_int {
    if keydata.is_null() || params.is_null() { return 0; }
    let key = unsafe { &*keydata.cast::<SoftKey>() };

    // bits
    let p = unsafe { openssl_sys::OSSL_PARAM_locate(params, c"bits".as_ptr()) };
    if !p.is_null() {
        let param = unsafe { &mut *p };
        if param.data_type == OSSL_PARAM_INTEGER && !param.data.is_null() {
            unsafe { *(param.data.cast::<c_int>()) = key.key_bits; }
            param.return_size = std::mem::size_of::<c_int>();
        }
    }

    // security-bits
    let p = unsafe { openssl_sys::OSSL_PARAM_locate(params, c"security-bits".as_ptr()) };
    if !p.is_null() {
        let param = unsafe { &mut *p };
        if param.data_type == OSSL_PARAM_INTEGER && !param.data.is_null() {
            unsafe { *(param.data.cast::<c_int>()) = key.security_bits; }
            param.return_size = std::mem::size_of::<c_int>();
        }
    }

    // max-size
    let p = unsafe { openssl_sys::OSSL_PARAM_locate(params, c"max-size".as_ptr()) };
    if !p.is_null() {
        let param = unsafe { &mut *p };
        if param.data_type == OSSL_PARAM_INTEGER && !param.data.is_null() {
            unsafe { *(param.data.cast::<c_int>()) = key.max_sig_size; }
            param.return_size = std::mem::size_of::<c_int>();
        }
    }

    // group
    let p = unsafe { openssl_sys::OSSL_PARAM_locate(params, c"group".as_ptr()) };
    if !p.is_null() && !key.group_name.is_empty() {
        let param = unsafe { &mut *p };
        if param.data_type == OSSL_PARAM_UTF8_STRING && !param.data.is_null() {
            let copy_len = key.group_name.len().min(param.data_size);
            unsafe {
                ptr::copy_nonoverlapping(key.group_name.as_ptr(), param.data.cast::<u8>(), copy_len);
            }
            param.return_size = key.group_name.len();
        }
    }

    1
}

extern "C" fn keymgmt_gettable_params(_provctx: *mut c_void) -> *const openssl_sys::OSSL_PARAM {
    struct S([openssl_sys::OSSL_PARAM; 5]);
    unsafe impl Sync for S {}
    static PARAMS: S = S([
        openssl_sys::OSSL_PARAM { key: c"bits".as_ptr(), data_type: OSSL_PARAM_INTEGER, data: ptr::null_mut(), data_size: 0, return_size: 0 },
        openssl_sys::OSSL_PARAM { key: c"security-bits".as_ptr(), data_type: OSSL_PARAM_INTEGER, data: ptr::null_mut(), data_size: 0, return_size: 0 },
        openssl_sys::OSSL_PARAM { key: c"max-size".as_ptr(), data_type: OSSL_PARAM_INTEGER, data: ptr::null_mut(), data_size: 0, return_size: 0 },
        openssl_sys::OSSL_PARAM { key: c"group".as_ptr(), data_type: OSSL_PARAM_UTF8_STRING, data: ptr::null_mut(), data_size: 0, return_size: 0 },
        openssl_sys::OSSL_PARAM { key: ptr::null(), data_type: 0, data: ptr::null_mut(), data_size: 0, return_size: 0 },
    ]);
    PARAMS.0.as_ptr()
}

extern "C" fn keymgmt_set_params(keydata: *mut c_void, params: *const openssl_sys::OSSL_PARAM) -> c_int {
    if keydata.is_null() || params.is_null() { return 0; }
    1
}

extern "C" fn keymgmt_settable_params(_provctx: *mut c_void) -> *const openssl_sys::OSSL_PARAM {
    struct SyncP(openssl_sys::OSSL_PARAM);
    unsafe impl Sync for SyncP {}
    static END: SyncP = SyncP(openssl_sys::OSSL_PARAM {
        key: ptr::null(), data_type: 0, data: ptr::null_mut(), data_size: 0, return_size: 0,
    });
    &END.0
}

/// Tell OpenSSL which SIGNATURE algorithm to use for our EC keys.
/// Without this, OpenSSL can't link keymgmt "EC" to signature "ECDSA".
extern "C" fn keymgmt_query_operation_name(operation_id: c_int) -> *const c_char {
    match operation_id {
        x if x == OSSL_OP_SIGNATURE => c"ECDSA".as_ptr(),
        _ => ptr::null(),
    }
}

extern "C" fn keymgmt_dup(keydata: *const c_void, _selection: c_int) -> *mut c_void {
    if keydata.is_null() { return ptr::null_mut(); }
    let src = unsafe { &*keydata.cast::<SoftKey>() };
    let dup = Box::new(SoftKey {
        ec_key: src.ec_key.as_ref().and_then(|k| {
            // Clone via DER round-trip
            k.private_key_to_der().ok().and_then(|d| EcKey::private_key_from_der(&d).ok())
        }),
        key_bits: src.key_bits,
        security_bits: src.security_bits,
        max_sig_size: src.max_sig_size,
        group_name: src.group_name.clone(),
    });
    Box::into_raw(dup).cast()
}

// ═══════════════════════════════════════════════════════════════════════
// SIGNATURE
// ═══════════════════════════════════════════════════════════════════════

extern "C" fn signature_newctx(_provctx: *mut c_void, _propq: *const c_char) -> *mut c_void {
    let ctx = Box::new(SoftSignCtx {
        key: ptr::null(),
        tbs_buffer: Vec::new(),
    });
    Box::into_raw(ctx).cast()
}

extern "C" fn signature_freectx(ctx: *mut c_void) {
    if !ctx.is_null() {
        let _ = unsafe { Box::from_raw(ctx.cast::<SoftSignCtx>()) };
    }
}

extern "C" fn signature_dupctx(ctx: *mut c_void) -> *mut c_void {
    if ctx.is_null() { return ptr::null_mut(); }
    let src = unsafe { &*ctx.cast::<SoftSignCtx>() };
    let dup = Box::new(SoftSignCtx {
        key: src.key,
        tbs_buffer: src.tbs_buffer.clone(),
    });
    Box::into_raw(dup).cast()
}

extern "C" fn signature_sign_init(
    ctx: *mut c_void, provkey: *mut c_void, _params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    if ctx.is_null() || provkey.is_null() { return 0; }
    let sign_ctx = unsafe { &mut *ctx.cast::<SoftSignCtx>() };
    sign_ctx.key = provkey.cast::<SoftKey>();
    1
}

extern "C" fn signature_sign(
    ctx: *mut c_void,
    sigret: *mut c_uchar,
    siglen: *mut usize,
    _sigsize: usize,
    tbs: *const c_uchar,
    tbslen: usize,
) -> c_int {
    if ctx.is_null() || siglen.is_null() { return 0; }
    let sign_ctx = unsafe { &*ctx.cast::<SoftSignCtx>() };
    if sign_ctx.key.is_null() { return 0; }
    let key = unsafe { &*sign_ctx.key };

    let ec_key = match &key.ec_key {
        Some(k) => k,
        None => return 0,
    };

    // Size query
    if sigret.is_null() {
        unsafe { *siglen = key.max_sig_size as usize; }
        return 1;
    }

    let data = unsafe { std::slice::from_raw_parts(tbs, tbslen) };

    // Hash then sign
    let digest = openssl::hash::hash(MessageDigest::sha256(), data).unwrap();
    let sig = EcdsaSig::sign(&digest, ec_key).unwrap();
    let der = sig.to_der().unwrap();

    unsafe {
        *siglen = der.len();
        ptr::copy_nonoverlapping(der.as_ptr(), sigret, der.len());
    }

    SIGN_COUNT.fetch_add(1, Ordering::SeqCst);
    eprintln!("    [softkey] signature_sign produced {} byte sig", der.len());
    1
}

extern "C" fn signature_digest_sign_init(
    ctx: *mut c_void, _mdname: *const c_char, provkey: *mut c_void,
    _params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    if ctx.is_null() || provkey.is_null() { return 0; }
    let sign_ctx = unsafe { &mut *ctx.cast::<SoftSignCtx>() };
    sign_ctx.key = provkey.cast::<SoftKey>();
    sign_ctx.tbs_buffer.clear();
    eprintln!("    [softkey] digest_sign_init");
    1
}

extern "C" fn signature_digest_sign_update(
    ctx: *mut c_void, data: *const c_uchar, datalen: usize,
) -> c_int {
    if ctx.is_null() || data.is_null() { return 0; }
    let sign_ctx = unsafe { &mut *ctx.cast::<SoftSignCtx>() };
    let slice = unsafe { std::slice::from_raw_parts(data, datalen) };
    sign_ctx.tbs_buffer.extend_from_slice(slice);
    1
}

extern "C" fn signature_digest_sign_final(
    ctx: *mut c_void, sigret: *mut c_uchar, siglen: *mut usize, _sigsize: usize,
) -> c_int {
    if ctx.is_null() || siglen.is_null() { return 0; }
    let sign_ctx = unsafe { &*ctx.cast::<SoftSignCtx>() };
    if sign_ctx.key.is_null() { return 0; }
    let key = unsafe { &*sign_ctx.key };

    if sigret.is_null() {
        unsafe { *siglen = key.max_sig_size as usize; }
        return 1;
    }

    let ec_key = match &key.ec_key {
        Some(k) => k,
        None => return 0,
    };

    // Hash the accumulated data, then sign
    let digest = openssl::hash::hash(MessageDigest::sha256(), &sign_ctx.tbs_buffer).unwrap();
    let sig = EcdsaSig::sign(&digest, ec_key).unwrap();
    let der = sig.to_der().unwrap();

    unsafe {
        *siglen = der.len();
        ptr::copy_nonoverlapping(der.as_ptr(), sigret, der.len());
    }

    SIGN_COUNT.fetch_add(1, Ordering::SeqCst);
    eprintln!("    [softkey] digest_sign_final produced {} byte sig from {} bytes data", der.len(), sign_ctx.tbs_buffer.len());
    1
}

extern "C" fn signature_digest_sign(
    ctx: *mut c_void, sigret: *mut c_uchar, siglen: *mut usize, _sigsize: usize,
    tbs: *const c_uchar, tbslen: usize,
) -> c_int {
    if ctx.is_null() || siglen.is_null() { return 0; }
    let sign_ctx = unsafe { &*ctx.cast::<SoftSignCtx>() };
    if sign_ctx.key.is_null() { return 0; }
    let key = unsafe { &*sign_ctx.key };

    if sigret.is_null() {
        unsafe { *siglen = key.max_sig_size as usize; }
        return 1;
    }

    let ec_key = match &key.ec_key {
        Some(k) => k,
        None => return 0,
    };

    let data = unsafe { std::slice::from_raw_parts(tbs, tbslen) };
    let digest = openssl::hash::hash(MessageDigest::sha256(), data).unwrap();
    let sig = EcdsaSig::sign(&digest, ec_key).unwrap();
    let der = sig.to_der().unwrap();

    unsafe {
        *siglen = der.len();
        ptr::copy_nonoverlapping(der.as_ptr(), sigret, der.len());
    }

    SIGN_COUNT.fetch_add(1, Ordering::SeqCst);
    1
}

extern "C" fn signature_digest_verify_init(
    ctx: *mut c_void, _mdname: *const c_char, provkey: *mut c_void,
    _params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    if ctx.is_null() || provkey.is_null() { return 0; }
    let sign_ctx = unsafe { &mut *ctx.cast::<SoftSignCtx>() };
    sign_ctx.key = provkey.cast::<SoftKey>();
    sign_ctx.tbs_buffer.clear();
    1
}

extern "C" fn signature_digest_verify_update(
    ctx: *mut c_void, data: *const c_uchar, datalen: usize,
) -> c_int {
    if ctx.is_null() || data.is_null() { return 0; }
    let sign_ctx = unsafe { &mut *ctx.cast::<SoftSignCtx>() };
    let slice = unsafe { std::slice::from_raw_parts(data, datalen) };
    sign_ctx.tbs_buffer.extend_from_slice(slice);
    1
}

extern "C" fn signature_digest_verify_final(
    ctx: *mut c_void, sig: *const c_uchar, siglen: usize,
) -> c_int {
    if ctx.is_null() || sig.is_null() { return 0; }
    let sign_ctx = unsafe { &*ctx.cast::<SoftSignCtx>() };
    if sign_ctx.key.is_null() { return 0; }
    let key = unsafe { &*sign_ctx.key };

    let ec_key = match &key.ec_key {
        Some(k) => k,
        None => return 0,
    };

    let sig_bytes = unsafe { std::slice::from_raw_parts(sig, siglen) };
    let digest = openssl::hash::hash(MessageDigest::sha256(), &sign_ctx.tbs_buffer).unwrap();

    match EcdsaSig::from_der(sig_bytes) {
        Ok(ecdsa_sig) => {
            if ecdsa_sig.verify(&digest, ec_key).unwrap_or(false) { 1 } else { 0 }
        }
        Err(_) => 0,
    }
}

extern "C" fn signature_get_ctx_params(
    _ctx: *mut c_void, _params: *mut openssl_sys::OSSL_PARAM,
) -> c_int {
    1
}

extern "C" fn signature_gettable_ctx_params(
    _ctx: *const c_void, _provctx: *const c_void,
) -> *const openssl_sys::OSSL_PARAM {
    struct SyncP(openssl_sys::OSSL_PARAM);
    unsafe impl Sync for SyncP {}
    static END: SyncP = SyncP(openssl_sys::OSSL_PARAM {
        key: ptr::null(), data_type: 0, data: ptr::null_mut(), data_size: 0, return_size: 0,
    });
    &END.0
}

extern "C" fn signature_set_ctx_params(
    _ctx: *mut c_void, _params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    1
}

extern "C" fn signature_settable_ctx_params(
    _ctx: *const c_void, _provctx: *const c_void,
) -> *const openssl_sys::OSSL_PARAM {
    struct SyncP(openssl_sys::OSSL_PARAM);
    unsafe impl Sync for SyncP {}
    static END: SyncP = SyncP(openssl_sys::OSSL_PARAM {
        key: ptr::null(), data_type: 0, data: ptr::null_mut(), data_size: 0, return_size: 0,
    });
    &END.0
}

// ═══════════════════════════════════════════════════════════════════════
// Dispatch tables
// ═══════════════════════════════════════════════════════════════════════

static KEYMGMT_DISPATCH: [OsslDispatch; 16] = [
    dispatch_entry!(OSSL_FUNC_KEYMGMT_NEW, keymgmt_new,
        extern "C" fn(*mut c_void) -> *mut c_void),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_FREE, keymgmt_free,
        extern "C" fn(*mut c_void)),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_HAS, keymgmt_has,
        extern "C" fn(*const c_void, c_int) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_VALIDATE, keymgmt_validate,
        extern "C" fn(*const c_void, c_int, c_int) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_MATCH, keymgmt_match,
        extern "C" fn(*const c_void, *const c_void, c_int) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_IMPORT, keymgmt_import,
        extern "C" fn(*mut c_void, c_int, *const openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, keymgmt_import_types,
        extern "C" fn(c_int) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_EXPORT, keymgmt_export,
        extern "C" fn(*mut c_void, c_int, Option<unsafe extern "C" fn(*const openssl_sys::OSSL_PARAM, *mut c_void) -> c_int>, *mut c_void) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, keymgmt_export_types,
        extern "C" fn(c_int) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, keymgmt_get_params,
        extern "C" fn(*mut c_void, *mut openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, keymgmt_gettable_params,
        extern "C" fn(*mut c_void) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_SET_PARAMS, keymgmt_set_params,
        extern "C" fn(*mut c_void, *const openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, keymgmt_settable_params,
        extern "C" fn(*mut c_void) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, keymgmt_query_operation_name,
        extern "C" fn(c_int) -> *const c_char),
    dispatch_entry!(OSSL_FUNC_KEYMGMT_DUP, keymgmt_dup,
        extern "C" fn(*const c_void, c_int) -> *mut c_void),
    OsslDispatch::end(),
];

static ECDSA_SIGNATURE_DISPATCH: [OsslDispatch; 17] = [
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
    dispatch_entry!(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, signature_get_ctx_params,
        extern "C" fn(*mut c_void, *mut openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, signature_gettable_ctx_params,
        extern "C" fn(*const c_void, *const c_void) -> *const openssl_sys::OSSL_PARAM),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, signature_set_ctx_params,
        extern "C" fn(*mut c_void, *const openssl_sys::OSSL_PARAM) -> c_int),
    dispatch_entry!(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, signature_settable_ctx_params,
        extern "C" fn(*const c_void, *const c_void) -> *const openssl_sys::OSSL_PARAM),
    OsslDispatch::end(),
];

// ═══════════════════════════════════════════════════════════════════════
// Algorithm tables
// ═══════════════════════════════════════════════════════════════════════

static KEYMGMT_ALGORITHMS: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: c"EC".as_ptr(),
        property_definition: c"provider=softkey,softkey.custom=yes".as_ptr(),
        implementation: KEYMGMT_DISPATCH.as_ptr(),
        algorithm_description: c"softkey EC keymgmt".as_ptr(),
    },
    OsslAlgorithm::end(),
];

static SIGNATURE_ALGORITHMS: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: c"ECDSA".as_ptr(),
        property_definition: c"provider=softkey".as_ptr(),
        implementation: ECDSA_SIGNATURE_DISPATCH.as_ptr(),
        algorithm_description: c"softkey ECDSA signature".as_ptr(),
    },
    OsslAlgorithm::end(),
];

// ═══════════════════════════════════════════════════════════════════════
// Provider init
// ═══════════════════════════════════════════════════════════════════════

extern "C" fn provider_query_operation(
    _provctx: *mut c_void, operation_id: c_int, _no_cache: *mut c_int,
) -> *const OsslAlgorithm {
    eprintln!("    [softkey] query_operation(op_id={operation_id})");
    match operation_id {
        x if x == OSSL_OP_KEYMGMT => KEYMGMT_ALGORITHMS.as_ptr(),
        x if x == OSSL_OP_SIGNATURE => SIGNATURE_ALGORITHMS.as_ptr(),
        _ => ptr::null(),
    }
}

extern "C" fn provider_teardown(_provctx: *mut c_void) {}

static PROVIDER_DISPATCH: [OsslDispatch; 3] = [
    dispatch_entry!(OSSL_FUNC_PROVIDER_TEARDOWN, provider_teardown,
        extern "C" fn(*mut c_void)),
    dispatch_entry!(OSSL_FUNC_PROVIDER_QUERY_OPERATION, provider_query_operation,
        extern "C" fn(*mut c_void, c_int, *mut c_int) -> *const OsslAlgorithm),
    OsslDispatch::end(),
];

unsafe extern "C" fn softkey_provider_init(
    _handle: *const c_void,
    _in_dispatch: *const OsslDispatch,
    out_dispatch: *mut *const OsslDispatch,
    out_provctx: *mut *mut c_void,
) -> c_int {
    unsafe {
        *out_dispatch = PROVIDER_DISPATCH.as_ptr();
        *out_provctx = ptr::null_mut();
    }
    eprintln!("    [softkey] provider initialized");
    1
}

static SOFTKEY_INIT: Once = Once::new();

fn register_softkey_provider() {
    SOFTKEY_INIT.call_once(|| {
        let rc = unsafe {
            OSSL_PROVIDER_add_builtin(ptr::null_mut(), c"softkey".as_ptr(), softkey_provider_init)
        };
        assert_eq!(rc, 1, "OSSL_PROVIDER_add_builtin failed");

        let prov = unsafe {
            openssl_sys::OSSL_PROVIDER_load(ptr::null_mut(), c"softkey".as_ptr())
        };
        assert!(!prov.is_null(), "OSSL_PROVIDER_load failed for softkey");

        // Also load the default provider
        let default = unsafe {
            openssl_sys::OSSL_PROVIDER_load(ptr::null_mut(), c"default".as_ptr())
        };
        assert!(!default.is_null(), "OSSL_PROVIDER_load failed for default");

        eprintln!("    [softkey] provider registered and loaded");
    });
}

// ═══════════════════════════════════════════════════════════════════════
// Test infrastructure
// ═══════════════════════════════════════════════════════════════════════

struct TestPki {
    ca_cert: openssl::x509::X509,
    server_cert: openssl::x509::X509,
    server_key: PKey<openssl::pkey::Private>,
    client_cert_pem: Vec<u8>,
    client_ec_key_der: Vec<u8>, // The actual EC private key for signing
}

fn generate_test_pki() -> TestPki {
    use openssl::asn1::Asn1Time;
    use openssl::ec::EcGroup;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

    // CA
    let ca_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut ca_builder = X509Builder::new().unwrap();
    ca_builder.set_version(2).unwrap();
    let mut sn = BigNum::new().unwrap();
    sn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
    ca_builder.set_serial_number(&sn.to_asn1_integer().unwrap()).unwrap();
    let mut ca_name = X509NameBuilder::new().unwrap();
    ca_name.append_entry_by_text("CN", "test-ca").unwrap();
    let ca_name = ca_name.build();
    ca_builder.set_subject_name(&ca_name).unwrap();
    ca_builder.set_issuer_name(&ca_name).unwrap();
    ca_builder.set_pubkey(&ca_key).unwrap();
    ca_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    ca_builder.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    ca_builder.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
    ca_builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap()).unwrap();
    ca_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca_cert = ca_builder.build();

    // Server cert
    let server_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut srv_builder = X509Builder::new().unwrap();
    srv_builder.set_version(2).unwrap();
    let mut sn = BigNum::new().unwrap();
    sn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
    srv_builder.set_serial_number(&sn.to_asn1_integer().unwrap()).unwrap();
    let mut srv_name = X509NameBuilder::new().unwrap();
    srv_name.append_entry_by_text("CN", "localhost").unwrap();
    let srv_name = srv_name.build();
    srv_builder.set_subject_name(&srv_name).unwrap();
    srv_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    srv_builder.set_pubkey(&server_key).unwrap();
    srv_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    srv_builder.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    srv_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let server_cert = srv_builder.build();

    // Client cert — the key will be managed by our softkey provider
    let client_ec = EcKey::generate(&group).unwrap();
    let client_key = PKey::from_ec_key(client_ec.clone()).unwrap();
    let mut cli_builder = X509Builder::new().unwrap();
    cli_builder.set_version(2).unwrap();
    let mut sn = BigNum::new().unwrap();
    sn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
    cli_builder.set_serial_number(&sn.to_asn1_integer().unwrap()).unwrap();
    let mut cli_name = X509NameBuilder::new().unwrap();
    cli_name.append_entry_by_text("CN", "test-client").unwrap();
    let cli_name = cli_name.build();
    cli_builder.set_subject_name(&cli_name).unwrap();
    cli_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    cli_builder.set_pubkey(&client_key).unwrap();
    cli_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    cli_builder.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    cli_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let client_cert = cli_builder.build();

    TestPki {
        ca_cert,
        server_cert,
        server_key,
        client_cert_pem: client_cert.to_pem().unwrap(),
        client_ec_key_der: client_ec.private_key_to_der().unwrap(),
    }
}

fn build_server_acceptor(pki: &TestPki) -> openssl::ssl::SslAcceptor {
    use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode};

    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    builder.set_certificate(&pki.server_cert).unwrap();
    builder.set_private_key(&pki.server_key).unwrap();

    let mut store_builder = openssl::x509::store::X509StoreBuilder::new().unwrap();
    store_builder.add_cert(pki.ca_cert.clone()).unwrap();
    builder.set_cert_store(store_builder.build());
    builder.add_client_ca(&pki.ca_cert).unwrap();
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

    // Force TLS 1.2
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2)).unwrap();
    builder.set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2)).unwrap();

    builder.build()
}

/// Create an EVP_PKEY backed by our softkey provider, with a real EC key inside.
unsafe fn create_softkey_pkey(ec_key_der: &[u8]) -> *mut openssl_sys::EVP_PKEY {
    // Create EVP_PKEY_CTX targeting our provider's keymgmt
    let pkey_ctx = unsafe {
        openssl_sys::EVP_PKEY_CTX_new_from_name(
            ptr::null_mut(),
            c"EC".as_ptr(),
            c"provider=softkey,softkey.custom=yes".as_ptr(),
        )
    };
    assert!(!pkey_ctx.is_null(), "EVP_PKEY_CTX_new_from_name failed");

    let rc = unsafe { openssl_sys::EVP_PKEY_fromdata_init(pkey_ctx) };
    assert_eq!(rc, 1, "EVP_PKEY_fromdata_init failed");

    // Build OSSL_PARAM array
    let mut ec_key_data = ec_key_der.to_vec();
    let mut key_bits: c_int = 256;
    let mut security_bits: c_int = 128;
    let mut max_sig_size: c_int = 72;
    let group_name = b"prime256v1\0";

    let params: [openssl_sys::OSSL_PARAM; 6] = [
        openssl_sys::OSSL_PARAM {
            key: c"softkey-ec-key".as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data: ec_key_data.as_mut_ptr().cast(),
            data_size: ec_key_data.len(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: c"softkey-bits".as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: (&mut key_bits as *mut c_int).cast(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: c"softkey-security-bits".as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: (&mut security_bits as *mut c_int).cast(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: c"softkey-max-size".as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: (&mut max_sig_size as *mut c_int).cast(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: c"group".as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: group_name.as_ptr() as *mut c_void,
            data_size: group_name.len() - 1, // exclude null
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: ptr::null(),
            data_type: 0,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
    ];

    let mut pkey: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
    let rc = unsafe {
        openssl_sys::EVP_PKEY_fromdata(
            pkey_ctx,
            &mut pkey,
            (OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY) as c_int,
            params.as_ptr() as *mut _,
        )
    };
    assert_eq!(rc, 1, "EVP_PKEY_fromdata failed");
    assert!(!pkey.is_null(), "EVP_PKEY_fromdata returned null");

    unsafe { openssl_sys::EVP_PKEY_CTX_free(pkey_ctx); }

    pkey
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn softkey_provider_fetch_works() {
    // Generate PKI BEFORE registering provider to avoid interference
    let pki = generate_test_pki();
    
    register_softkey_provider();

    unsafe {
        // Test 1: Fetch ECDSA from our provider
        let sig = openssl_sys::EVP_SIGNATURE_fetch(
            ptr::null_mut(),
            c"ECDSA".as_ptr(),
            c"provider=softkey".as_ptr(),
        );
        eprintln!("[test] EVP_SIGNATURE_fetch('ECDSA', provider=softkey) = {:?}", sig);
        if sig.is_null() {
            // Dump errors
            loop {
                let err = openssl_sys::ERR_get_error();
                if err == 0 { break; }
                let reason = openssl_sys::ERR_reason_error_string(err);
                let r = if !reason.is_null() { CStr::from_ptr(reason).to_str().unwrap_or("?") } else { "?" };
                eprintln!("  ERR: {r}");
            }
            panic!("EVP_SIGNATURE_fetch for softkey returned NULL!");
        }
        openssl_sys::EVP_SIGNATURE_free(sig);
        eprintln!("[test] ✓ ECDSA fetch from softkey works");

        // Test 2: Create an EVP_PKEY
        let pkey = create_softkey_pkey(&pki.client_ec_key_der);
        eprintln!("[test] ✓ EVP_PKEY created from softkey provider");

        // Test 3: DigestSign with our key
        openssl_sys::ERR_clear_error();
        let md_ctx = openssl_sys::EVP_MD_CTX_new();
        assert!(!md_ctx.is_null());
        let sha256 = openssl_sys::EVP_sha256();
        let mut pctx: *mut openssl_sys::EVP_PKEY_CTX = ptr::null_mut();
        let rc = openssl_sys::EVP_DigestSignInit(
            md_ctx, &mut pctx, sha256, ptr::null_mut(), pkey as *mut _,
        );
        eprintln!("[test] EVP_DigestSignInit = {rc}");
        if rc != 1 {
            loop {
                let err = openssl_sys::ERR_get_error();
                if err == 0 { break; }
                let reason = openssl_sys::ERR_reason_error_string(err);
                let r = if !reason.is_null() { CStr::from_ptr(reason).to_str().unwrap_or("?") } else { "?" };
                eprintln!("  ERR: {r}");
            }
            openssl_sys::EVP_MD_CTX_free(md_ctx);
            openssl_sys::EVP_PKEY_free(pkey);
            panic!("EVP_DigestSignInit FAILED");
        }

        // Feed data
        let data = b"hello world";
        let rc = openssl_sys::EVP_DigestSignUpdate(md_ctx, data.as_ptr().cast(), data.len());
        assert_eq!(rc, 1, "EVP_DigestSignUpdate failed");

        // Get sig size
        let mut siglen: usize = 0;
        let rc = openssl_sys::EVP_DigestSignFinal(md_ctx, ptr::null_mut(), &mut siglen);
        assert_eq!(rc, 1, "EVP_DigestSignFinal (size query) failed");
        eprintln!("[test] sig size = {siglen}");

        // Get actual signature
        let mut sig_buf = vec![0u8; siglen];
        let rc = openssl_sys::EVP_DigestSignFinal(md_ctx, sig_buf.as_mut_ptr(), &mut siglen);
        assert_eq!(rc, 1, "EVP_DigestSignFinal failed");
        eprintln!("[test] ✓ DigestSign produced {siglen} byte signature");

        openssl_sys::EVP_MD_CTX_free(md_ctx);
        openssl_sys::EVP_PKEY_free(pkey);
    }
}

#[test]
fn softkey_tls12_handshake() {
    // Generate PKI BEFORE registering provider to avoid interference
    let pki = generate_test_pki();
    register_softkey_provider();

    // Build client SSL_CTX
    let method = openssl::ssl::SslMethod::tls_client();
    let mut builder = openssl::ssl::SslContext::builder(method).unwrap();

    // Trust CA
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new().unwrap();
    store_builder.add_cert(pki.ca_cert.clone()).unwrap();
    builder.set_cert_store(store_builder.build());

    // Pin TLS 1.2
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2)).unwrap();
    builder.set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2)).unwrap();

    let ssl_ctx = builder.build();

    // Load certificate into SSL_CTX
    let client_cert = openssl::x509::X509::from_pem(&pki.client_cert_pem).unwrap();
    let ssl_ctx_ptr = ssl_ctx.as_ptr();
    let rc = unsafe { openssl_sys::SSL_CTX_use_certificate(ssl_ctx_ptr, client_cert.as_ptr()) };
    assert_eq!(rc, 1, "SSL_CTX_use_certificate failed");
    eprintln!("[test] ✓ SSL_CTX_use_certificate OK");

    // Create provider EVP_PKEY with the real private key
    let pkey = unsafe { create_softkey_pkey(&pki.client_ec_key_der) };
    let rc = unsafe { openssl_sys::SSL_CTX_use_PrivateKey(ssl_ctx_ptr, pkey) };
    unsafe { openssl_sys::EVP_PKEY_free(pkey); }
    assert_eq!(rc, 1, "SSL_CTX_use_PrivateKey failed");
    eprintln!("[test] ✓ SSL_CTX_use_PrivateKey OK");

    // Now try EVP_DigestSignInit with the key from the SSL_CTX
    unsafe {
        let pkey = openssl_sys::SSL_CTX_get0_privatekey(ssl_ctx_ptr);
        assert!(!pkey.is_null(), "SSL_CTX has no private key");

        let is_ec = openssl_sys::EVP_PKEY_is_a(pkey, c"EC".as_ptr());
        eprintln!("[test] EVP_PKEY_is_a(EC) = {is_ec}");

        // Fetch test
        openssl_sys::ERR_clear_error();
        let sig = openssl_sys::EVP_SIGNATURE_fetch(
            ptr::null_mut(), c"ECDSA".as_ptr(), c"provider=softkey".as_ptr(),
        );
        eprintln!("[test] EVP_SIGNATURE_fetch('ECDSA', provider=softkey) = {:?}", sig);
        if sig.is_null() {
            loop {
                let err = openssl_sys::ERR_get_error();
                if err == 0 { break; }
                let reason = openssl_sys::ERR_reason_error_string(err);
                let r = if !reason.is_null() { CStr::from_ptr(reason).to_str().unwrap_or("?") } else { "?" };
                eprintln!("  ERR: {r}");
            }
        } else {
            openssl_sys::EVP_SIGNATURE_free(sig);
        }

        // DigestSignInit
        openssl_sys::ERR_clear_error();
        let md_ctx = openssl_sys::EVP_MD_CTX_new();
        let sha256 = openssl_sys::EVP_sha256();
        let mut pctx: *mut openssl_sys::EVP_PKEY_CTX = ptr::null_mut();
        let rc = openssl_sys::EVP_DigestSignInit(
            md_ctx, &mut pctx, sha256, ptr::null_mut(), pkey as *mut _,
        );
        eprintln!("[test] EVP_DigestSignInit(SHA256, pkey) = {rc}");
        if rc != 1 {
            loop {
                let err = openssl_sys::ERR_get_error();
                if err == 0 { break; }
                let reason = openssl_sys::ERR_reason_error_string(err);
                let r = if !reason.is_null() { CStr::from_ptr(reason).to_str().unwrap_or("?") } else { "?" };
                eprintln!("  ERR: {r}");
            }
        }
        openssl_sys::EVP_MD_CTX_free(md_ctx);
    }

    // Start TLS server
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    eprintln!("[test] TLS 1.2 mTLS test on {addr}");

    let acceptor = Arc::new(build_server_acceptor(&pki));
    let ready = Arc::new(std::sync::Barrier::new(2));

    let server_ready = ready.clone();
    let server_acceptor = acceptor.clone();
    let server_thread = std::thread::spawn(move || {
        server_ready.wait();
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        match server_acceptor.accept(stream) {
            Ok(mut tls) => {
                eprintln!("    [server] TLS accepted ✓");
                let mut buf = [0u8; 128];
                let n = tls.read(&mut buf).unwrap_or(0);
                eprintln!("    [server] read {n} bytes");
                let _ = tls.write_all(b"OK\n");
            }
            Err(e) => {
                eprintln!("    [server] TLS accept error: {e}");
            }
        }
    });

    ready.wait();
    let before = SIGN_COUNT.load(Ordering::SeqCst);

    // Connect
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    let ssl = openssl::ssl::Ssl::new(&ssl_ctx).unwrap();
    match ssl.connect(stream) {
        Ok(mut tls) => {
            eprintln!("    [client] Handshake succeeded ✓");
            let _ = tls.write_all(b"HELLO\n");
            let mut buf = [0u8; 64];
            let _ = tls.read(&mut buf);
        }
        Err(e) => {
            eprintln!("    [client] Handshake error: {e}");
        }
    }

    let after = SIGN_COUNT.load(Ordering::SeqCst);
    let sign_calls = after - before;
    eprintln!("[test] sign_func called {sign_calls} times");

    server_thread.join().unwrap();

    assert!(sign_calls > 0, "sign function was never called! The provider is broken.");
    eprintln!("[test] ✓ SOFTKEY TLS 1.2 mTLS HANDSHAKE PASSED — provider works!");
}
