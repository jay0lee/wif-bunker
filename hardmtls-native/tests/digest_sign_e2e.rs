//! End-to-end test: simulate the TLS `EVP_DigestSign` flow.
//!
//! This test reproduces the exact sequence OpenSSL's TLS stack uses:
//! 1. Create a provider key via `EVP_PKEY_fromdata`
//! 2. Call `EVP_DigestSignInit_ex` (which triggers `do_sigver_init`)
//! 3. Call `EVP_DigestSign` to produce a signature
//!
//! Run with: cargo test --test digest_sign_e2e -- --nocapture
#![allow(missing_docs)]

use std::ffi::{c_char, c_int, c_uchar, c_void, CStr};
use std::ptr;

// Pre-built self-signed EC P-256 test certificate (avoid provider conflicts during signing).
const EC_CERT_PEM: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIIBkTCB+wIUE4f8vXWVFHxKJFv7F9Ay/bMBGhQwCgYIKoZIzj0EAwIwFDESMBAG\n",
    "A1UEAwwJdGVzdC1lYzAxMB4XDTI2MDgwNzIyMDAwMFoXDTI3MDgwNzIyMDAwMFow\n",
    "FDESMBAGA1UEAwwJdGVzdC1lYzAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n",
    "qG3RS1GmdJg2MFXZ3L6ghFJr3qdN/IhJ3VwVQkPpZJG7EjP0iaEIJL3jFZaEyUBZ\n",
    "Oe/IFZgYI0jOLU5X2aMhMB8wHQYDVR0OBBYEFPzXh1hxJM95T1EZAiZr7s5bLRYa\n",
    "MAoGCCqGSM49BAMCA0gAMEUCIQD+aaAZOsIzC1ViCZhUXNDz6eBjCwXcE+V5N6sj\n",
    "zBPYBgIgYlZLw4J9VDQ0hVMlUJn9FWUmifm0W+ON1hLOJBJUQ2U=\n",
    "-----END CERTIFICATE-----\n",
);

/// Dummy sign function that produces a fixed 72-byte "signature" for EC keys.
/// In real usage, this would be the callback from google-auth that calls SignForPython.
#[allow(unsafe_code)]
unsafe extern "C" fn dummy_ec_sign(
    sig: *mut c_uchar,
    sig_len: *mut usize,
    _tbs: *const c_uchar,
    _tbs_len: usize,
) -> c_int {
    if sig.is_null() {
        // Size query
        unsafe { *sig_len = 72 };
        return 1;
    }
    // Write a fake DER-encoded ECDSA signature (valid structure)
    // SEQUENCE { INTEGER r, INTEGER s }
    let fake_sig: [u8; 70] = [
        0x30, 0x44, // SEQUENCE, 68 bytes
        0x02, 0x20, // INTEGER, 32 bytes (r)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x02, 0x20, // INTEGER, 32 bytes (s)
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40,
    ];
    unsafe {
        ptr::copy_nonoverlapping(fake_sig.as_ptr(), sig, fake_sig.len());
        *sig_len = fake_sig.len();
    }
    eprintln!(
        ">>> DUMMY_EC_SIGN called! tbs_len={_tbs_len}, produced {} bytes",
        fake_sig.len()
    );
    1
}

fn dump_openssl_errors(prefix: &str) {
    #[allow(unsafe_code)]
    unsafe {
        loop {
            let err = openssl_sys::ERR_get_error();
            if err == 0 {
                break;
            }
            let reason = openssl_sys::ERR_reason_error_string(err);
            let lib = openssl_sys::ERR_lib_error_string(err);
            let lib_s = if !lib.is_null() {
                CStr::from_ptr(lib).to_str().unwrap_or("?")
            } else {
                "?"
            };
            let rsn_s = if !reason.is_null() {
                CStr::from_ptr(reason).to_str().unwrap_or("?")
            } else {
                "?"
            };
            eprintln!("  {prefix} OpenSSL error: lib={lib_s} reason={rsn_s} code={err:#x}");
        }
    }
}

extern "C" {
    fn EVP_MD_CTX_new() -> *mut c_void;
    fn EVP_MD_CTX_free(ctx: *mut c_void);

    fn EVP_DigestSignInit_ex(
        ctx: *mut c_void,                       // EVP_MD_CTX *
        pctx: *mut *mut c_void,                 // EVP_PKEY_CTX **
        mdname: *const c_char,                  // digest name
        libctx: *mut c_void,                    // OSSL_LIB_CTX *
        props: *const c_char,                   // property query
        pkey: *mut openssl_sys::EVP_PKEY,       // EVP_PKEY *
        params: *const openssl_sys::OSSL_PARAM, // extra params
    ) -> c_int;

    fn EVP_DigestSign(
        ctx: *mut c_void,     // EVP_MD_CTX *
        sigret: *mut c_uchar, // output buffer
        siglen: *mut usize,   // in/out signature length
        tbs: *const c_uchar,  // to-be-signed data
        tbslen: usize,        // length of tbs
    ) -> c_int;

    fn EVP_KEYMGMT_get0_provider(keymgmt: *const c_void) -> *const c_void;
    fn EVP_KEYMGMT_get0_name(keymgmt: *const c_void) -> *const c_char;
    fn EVP_PKEY_get0_type_name(pkey: *const openssl_sys::EVP_PKEY) -> *const c_char;
}

#[test]
fn ec_digest_sign_via_provider() {
    let _ = env_logger::try_init();

    // ── Step 1: Register the provider ──────────────────────────────────
    eprintln!("\n=== Step 1: Register provider ===");
    hardmtls::provider::register_provider().expect("register_provider failed");
    eprintln!("  ✓ Provider registered");

    // ── Step 2: Create provider EVP_PKEY (same flow as ssl_ctx.rs) ──────
    eprintln!("\n=== Step 2: Create provider EVP_PKEY ===");
    #[allow(unsafe_code)]
    let pkey = unsafe { create_ec_provider_pkey() };
    assert!(!pkey.is_null(), "Failed to create provider EVP_PKEY");

    // Print key info
    #[allow(unsafe_code)]
    unsafe {
        let type_name = EVP_PKEY_get0_type_name(pkey);
        if !type_name.is_null() {
            let name = CStr::from_ptr(type_name);
            eprintln!("  EVP_PKEY type name: {:?}", name);
        }

        let key_size = openssl_sys::EVP_PKEY_get_size(pkey);
        let key_bits = openssl_sys::EVP_PKEY_get_bits(pkey);
        let key_security_bits = openssl_sys::EVP_PKEY_get_security_bits(pkey);
        eprintln!("  EVP_PKEY size={key_size}, bits={key_bits}, security_bits={key_security_bits}");
    }

    // ── Step 3: EVP_DigestSignInit_ex (simulates TLS stack) ────────────
    eprintln!("\n=== Step 3: EVP_DigestSignInit_ex ===");
    #[allow(unsafe_code)]
    let (md_ctx, rc) = unsafe {
        let md_ctx = EVP_MD_CTX_new();
        assert!(!md_ctx.is_null(), "EVP_MD_CTX_new returned NULL");

        let mut pctx: *mut c_void = ptr::null_mut();

        openssl_sys::ERR_clear_error();

        // This is exactly what tls_construct_cert_verify does:
        // EVP_DigestSignInit_ex(mctx, &pctx, "SHA256", sctx->libctx, sctx->propq, pkey, params)
        // In the default case, libctx=NULL, propq=NULL
        let rc = EVP_DigestSignInit_ex(
            md_ctx,
            &mut pctx,
            c"SHA256".as_ptr(), // digest name
            ptr::null_mut(),    // libctx = NULL (default)
            ptr::null(),        // propq = NULL (default)
            pkey,               // our provider key
            ptr::null(),        // no extra params
        );

        eprintln!("  EVP_DigestSignInit_ex returned: {rc}");
        if rc <= 0 {
            eprintln!("  *** FAILED! ***");
            dump_openssl_errors("DigestSignInit");
        } else {
            eprintln!("  ✓ DigestSignInit succeeded");
            if !pctx.is_null() {
                eprintln!("  pctx = {:?}", pctx);
            }
        }

        (md_ctx, rc)
    };

    if rc <= 0 {
        #[allow(unsafe_code)]
        unsafe {
            EVP_MD_CTX_free(md_ctx);
            openssl_sys::EVP_PKEY_free(pkey);
        }
        panic!("EVP_DigestSignInit_ex failed! The provider signing path is broken.");
    }

    // ── Step 4: EVP_DigestSign (size query) ────────────────────────────
    eprintln!("\n=== Step 4: EVP_DigestSign (size query) ===");
    let test_data = b"test data for signing";
    let mut siglen: usize = 0;

    #[allow(unsafe_code)]
    let rc = unsafe {
        EVP_DigestSign(
            md_ctx,
            ptr::null_mut(), // NULL = size query
            &mut siglen,
            test_data.as_ptr(),
            test_data.len(),
        )
    };
    eprintln!("  EVP_DigestSign (size query) returned: {rc}, siglen={siglen}");
    assert!(rc > 0, "EVP_DigestSign size query failed");

    // ── Step 5: EVP_DigestSign (actual signing) ─────────────────────────
    eprintln!("\n=== Step 5: EVP_DigestSign (actual signing) ===");
    let mut sig = vec![0u8; siglen];

    #[allow(unsafe_code)]
    let rc = unsafe {
        EVP_DigestSign(
            md_ctx,
            sig.as_mut_ptr(),
            &mut siglen,
            test_data.as_ptr(),
            test_data.len(),
        )
    };
    eprintln!("  EVP_DigestSign returned: {rc}, siglen={siglen}");

    if rc <= 0 {
        dump_openssl_errors("DigestSign");
        #[allow(unsafe_code)]
        unsafe {
            EVP_MD_CTX_free(md_ctx);
            openssl_sys::EVP_PKEY_free(pkey);
        }
        panic!("EVP_DigestSign failed!");
    }

    sig.truncate(siglen);
    eprintln!("  ✓ Signature produced: {} bytes", siglen);
    eprintln!("  First 16 bytes: {:02x?}", &sig[..sig.len().min(16)]);

    // ── Cleanup ────────────────────────────────────────────────────────
    #[allow(unsafe_code)]
    unsafe {
        EVP_MD_CTX_free(md_ctx);
        openssl_sys::EVP_PKEY_free(pkey);
    }

    eprintln!("\n=== ALL STEPS PASSED ===");
}

/// Create an EC P-256 provider key using the same flow as `ssl_ctx::create_provider_pkey`.
#[allow(unsafe_code)]
unsafe fn create_ec_provider_pkey() -> *mut openssl_sys::EVP_PKEY {
    use hardmtls::provider_ffi::{
        HARDMTLS_PARAM_GROUP_NAME, HARDMTLS_PARAM_KEY_BITS, HARDMTLS_PARAM_MAX_SIZE,
        HARDMTLS_PARAM_SECURITY_BITS, HARDMTLS_PARAM_SIGN_FUNC, OSSL_PARAM_INTEGER,
        OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING,
    };

    let pkey_ctx = openssl_sys::EVP_PKEY_CTX_new_from_name(
        ptr::null_mut(),
        c"EC".as_ptr(),
        c"provider=hardmtls,hardmtls.sign=yes".as_ptr(),
    );
    if pkey_ctx.is_null() {
        eprintln!("  EVP_PKEY_CTX_new_from_name(EC) failed!");
        dump_openssl_errors("CTX_new_from_name");
        return ptr::null_mut();
    }
    eprintln!("  EVP_PKEY_CTX created: {:?}", pkey_ctx);

    let rc = openssl_sys::EVP_PKEY_fromdata_init(pkey_ctx);
    if rc != 1 {
        eprintln!("  fromdata_init failed!");
        dump_openssl_errors("fromdata_init");
        openssl_sys::EVP_PKEY_CTX_free(pkey_ctx);
        return ptr::null_mut();
    }

    // Build params
    let mut sign_func_bytes = dummy_ec_sign as hardmtls::SignCallback;
    let mut key_bits: c_int = 256;
    let mut security_bits: c_int = 128;
    let mut max_sig_size: c_int = 72;
    let group_name = c"prime256v1";

    let params = [
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_SIGN_FUNC.as_ptr(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data: (&mut sign_func_bytes as *mut hardmtls::SignCallback).cast::<c_void>(),
            data_size: std::mem::size_of::<hardmtls::SignCallback>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_KEY_BITS.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: (&mut key_bits as *mut c_int).cast::<c_void>(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_SECURITY_BITS.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: (&mut security_bits as *mut c_int).cast::<c_void>(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_MAX_SIZE.as_ptr(),
            data_type: OSSL_PARAM_INTEGER,
            data: (&mut max_sig_size as *mut c_int).cast::<c_void>(),
            data_size: std::mem::size_of::<c_int>(),
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: HARDMTLS_PARAM_GROUP_NAME.as_ptr(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: group_name.as_ptr().cast_mut().cast::<c_void>(),
            data_size: group_name.to_bytes().len(),
            return_size: 0,
        },
        // Sentinel
        openssl_sys::OSSL_PARAM {
            key: ptr::null(),
            data_type: 0,
            data: ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
    ];

    let mut pkey: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
    let rc = openssl_sys::EVP_PKEY_fromdata(
        pkey_ctx,
        &mut pkey,
        openssl_sys::EVP_PKEY_KEYPAIR,
        params.as_ptr().cast_mut(),
    );

    openssl_sys::EVP_PKEY_CTX_free(pkey_ctx);

    if rc != 1 || pkey.is_null() {
        eprintln!("  EVP_PKEY_fromdata failed!");
        dump_openssl_errors("fromdata");
        return ptr::null_mut();
    }

    eprintln!("  ✓ EVP_PKEY created: {:?}", pkey);
    pkey
}
