import re

with open("tests/mtls_handshake.rs", "r") as f:
    content = f.read()

# Add a global to hold the private key
global_key_code = """
use std::sync::Mutex;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::hash::MessageDigest;

lazy_static::lazy_static! {
    static ref TEST_CLIENT_KEY: Mutex<Option<PKey<Private>>> = Mutex::new(None);
}
"""
content = re.sub(
    r'use std::sync::atomic::\{AtomicUsize, Ordering\};',
    r'use std::sync::atomic::{AtomicUsize, Ordering};\n' + global_key_code,
    content
)

# Update test_sign to use the real key
new_test_sign = """
unsafe extern "C" fn test_sign(
    sig: *mut c_uchar,
    sig_len: *mut usize,
    tbs: *const c_uchar,
    tbs_len: usize,
) -> c_int {
    SIGN_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
    eprintln!(
        "    >>> test_sign invoked (call #{})",
        SIGN_CALL_COUNT.load(Ordering::SeqCst)
    );

    if sig.is_null() {
        unsafe { *sig_len = 256 }; // Max RSA/ECDSA size
        return 1;
    }

    let tbs_slice = unsafe { std::slice::from_raw_parts(tbs, tbs_len) };
    
    // Get the real key
    let guard = TEST_CLIENT_KEY.lock().unwrap();
    if let Some(pkey) = &*guard {
        // In TLS 1.2/1.3, the TBS data is ALREADY hashed by OpenSSL for ECDSA/RSA!
        // Wait, for RSA PKCS1 it's the raw hash.
        // For ECDSA, it's the raw hash.
        // We can use a raw signer!
        // But openssl-sys doesn't easily expose raw ECDSA_sign.
        // Let's use ECDSA_sign directly from openssl-sys!
        let ec_key = openssl_sys::EVP_PKEY_get0_EC_KEY(pkey.as_ptr());
        if !ec_key.is_null() {
            let mut out_len = 0;
            let rc = openssl_sys::ECDSA_sign(
                0,
                tbs,
                tbs_len as i32,
                sig,
                &mut out_len,
                ec_key,
            );
            if rc == 1 {
                unsafe { *sig_len = out_len as usize };
                return 1;
            }
        }
    }
    
    // Fallback if no key or error
    let dummy_sig: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    let max = unsafe { *sig_len };
    if dummy_sig.len() > max {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(dummy_sig.as_ptr(), sig, dummy_sig.len());
        *sig_len = dummy_sig.len();
    }
    1
}
"""
content = re.sub(
    r'unsafe extern "C" fn test_sign\(.*?\) -> c_int \{.*?\n\}' + r'\n' + r'// ════════════',
    new_test_sign + '\n// ════════════',
    content,
    flags=re.DOTALL
)

# Set the key in build_test_pki
set_key_code = """
    let client_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    *TEST_CLIENT_KEY.lock().unwrap() = Some(client_key.clone());
"""
content = re.sub(
    r'let client_key = PKey::from_ec_key\(EcKey::generate\(&group\)\.unwrap\(\)\)\.unwrap\(\);',
    set_key_code,
    content
)

with open("tests/mtls_handshake.rs", "w") as f:
    f.write(content)
