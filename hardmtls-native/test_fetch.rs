use hardmtls::provider::provider_init;

fn main() {
    unsafe {
        let mut provctx = std::ptr::null_mut();
        let mut out = std::ptr::null();
        provider_init(
            std::ptr::null(),
            std::ptr::null(),
            &mut out,
            &mut provctx,
        );
        let cstr = std::ffi::CString::new("hardmtls").unwrap();
        openssl_sys::OSSL_PROVIDER_add_builtin(std::ptr::null_mut(), cstr.as_ptr(), Some(provider_init));
        openssl_sys::OSSL_PROVIDER_load(std::ptr::null_mut(), cstr.as_ptr());
        
        let sig = openssl_sys::EVP_SIGNATURE_fetch(
            std::ptr::null_mut(),
            c"ECDSA".as_ptr(),
            c"provider=hardmtls".as_ptr(),
        );
        if sig.is_null() {
            openssl_sys::ERR_print_errors_fp(openssl_sys::core::ffi::libc::stdout as *mut _);
        } else {
            println!("Success!");
        }
    }
}
