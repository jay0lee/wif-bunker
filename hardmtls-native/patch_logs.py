import re

with open("src/provider.rs", "r") as f:
    content = f.read()

# Add logging to signature parameter functions
content = content.replace('extern "C" fn signature_get_ctx_params(', 'extern "C" fn signature_get_ctx_params(\n    _ctx: *mut std::ffi::c_void, _params: *mut openssl_sys::OSSL_PARAM\n) -> std::ffi::c_int {\n    log::debug!("hardmTLS provider: signature_get_ctx_params");\n    1\n}\n\n#[allow(dead_code)]\nextern "C" fn signature_get_ctx_params_old(')

content = content.replace('extern "C" fn signature_gettable_ctx_params(', 'extern "C" fn signature_gettable_ctx_params(\n    _ctx: *const std::ffi::c_void, _provctx: *const std::ffi::c_void\n) -> *const openssl_sys::OSSL_PARAM {\n    log::debug!("hardmTLS provider: signature_gettable_ctx_params");\n    std::ptr::null()\n}\n\n#[allow(dead_code)]\nextern "C" fn signature_gettable_ctx_params_old(')

content = content.replace('extern "C" fn signature_set_ctx_params(', 'extern "C" fn signature_set_ctx_params(\n    _ctx: *mut std::ffi::c_void, _params: *const openssl_sys::OSSL_PARAM\n) -> std::ffi::c_int {\n    log::debug!("hardmTLS provider: signature_set_ctx_params");\n    1\n}\n\n#[allow(dead_code)]\nextern "C" fn signature_set_ctx_params_old(')

content = content.replace('extern "C" fn signature_settable_ctx_params(', 'extern "C" fn signature_settable_ctx_params(\n    _ctx: *const std::ffi::c_void, _provctx: *const std::ffi::c_void\n) -> *const openssl_sys::OSSL_PARAM {\n    log::debug!("hardmTLS provider: signature_settable_ctx_params");\n    std::ptr::null()\n}\n\n#[allow(dead_code)]\nextern "C" fn signature_settable_ctx_params_old(')

with open("src/provider.rs", "w") as f:
    f.write(content)
