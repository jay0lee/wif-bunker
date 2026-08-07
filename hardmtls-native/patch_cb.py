import re

with open("src/ssl_ctx.rs", "r") as f:
    content = f.read()

cb_func = """
#[allow(unsafe_code)]
extern "C" fn client_cert_cb(
    ssl: *mut openssl_sys::SSL,
    x509: *mut *mut openssl_sys::X509,
    pkey: *mut *mut openssl_sys::EVP_PKEY,
) -> std::ffi::c_int {
    unsafe {
        let ssl_ctx = openssl_sys::SSL_get_SSL_CTX(ssl);
        if ssl_ctx.is_null() { return 0; }
        
        let cert = openssl_sys::SSL_CTX_get0_certificate(ssl_ctx);
        let private_key = openssl_sys::SSL_CTX_get0_privatekey(ssl_ctx);

        if cert.is_null() || private_key.is_null() {
            return 0;
        }

        openssl_sys::X509_up_ref(cert);
        openssl_sys::EVP_PKEY_up_ref(private_key);

        *x509 = cert;
        *pkey = private_key;

        log::debug!("hardmTLS: client_cert_cb invoked, forcing client cert selection");
        1
    }
}
"""

if "fn client_cert_cb(" not in content:
    content += cb_func

set_cb = r"""    // SAFETY: ssl_ctx and pkey are valid.
    unsafe {
        openssl_sys::SSL_CTX_use_PrivateKey(ssl_ctx.as_ptr(), pkey);
    }"""

new_set_cb = r"""    // SAFETY: ssl_ctx and pkey are valid.
    unsafe {
        openssl_sys::SSL_CTX_use_PrivateKey(ssl_ctx.as_ptr(), pkey);
        openssl_sys::SSL_CTX_set_client_cert_cb(ssl_ctx.as_ptr(), Some(client_cert_cb));
    }"""

content = content.replace(set_cb, new_set_cb)

with open("src/ssl_ctx.rs", "w") as f:
    f.write(content)
