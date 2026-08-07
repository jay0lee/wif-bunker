import re

with open("tests/mtls_handshake.rs", "r") as f:
    content = f.read()

bad_call = r"""    hardmtls::ConfigureSslContext\(
        &mut ctx_builder,
        &pki.client_cert_pem,
        dummy_sign,
        true,
    \)\.unwrap\(\);"""

good_call = r"""    let cert_cstr = std::ffi::CString::new(pki.client_cert_pem.clone()).unwrap();
    let ssl_ctx_ptr = ctx_builder.as_ptr() as *mut std::ffi::c_void;
    let rc = unsafe {
        hardmtls::ConfigureSslContext(
            test_sign,
            cert_cstr.as_ptr(),
            ssl_ctx_ptr,
        )
    };
    assert_eq!(rc, 1, "ConfigureSslContext failed");"""

content = re.sub(bad_call, good_call, content)

with open("tests/mtls_handshake.rs", "w") as f:
    f.write(content)

