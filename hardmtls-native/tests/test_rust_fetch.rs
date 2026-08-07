use std::ptr;

#[test]
fn test_fetch_ecdsa() {
    unsafe {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .try_init();

        let mut provctx = ptr::null_mut();
        let mut out = ptr::null();
        hardmtls::provider::provider_init(ptr::null(), ptr::null(), &mut out, &mut provctx);
        let cstr = std::ffi::CString::new("hardmtls").unwrap();
        openssl_sys::OSSL_PROVIDER_add_builtin(
            ptr::null_mut(),
            cstr.as_ptr(),
            Some(hardmtls::provider::provider_init),
        );
        openssl_sys::OSSL_PROVIDER_load(ptr::null_mut(), cstr.as_ptr());

        let sig = openssl_sys::EVP_SIGNATURE_fetch(
            ptr::null_mut(),
            c"ECDSA".as_ptr(),
            c"provider=hardmtls".as_ptr(),
        );
        if sig.is_null() {
            openssl_sys::ERR_print_errors_fp(openssl_sys::core::ffi::libc::stdout as *mut _);
            panic!("Fetch failed!");
        } else {
            println!("Success!");
        }
    }
}
