import re

with open("src/provider.rs", "r") as f:
    content = f.read()

helpers = """
#[allow(unsafe_code)]
fn get_param_utf8_string(param: *const openssl_sys::OSSL_PARAM) -> Option<String> {
    if param.is_null() {
        return None;
    }
    unsafe {
        let p = &*param;
        if p.data_type == openssl_sys::OSSL_PARAM_UTF8_STRING && !p.data.is_null() {
            let cstr = std::ffi::CStr::from_ptr(p.data.cast::<std::ffi::c_char>());
            return cstr.to_str().ok().map(|s| s.to_string());
        }
    }
    None
}
"""

content = re.sub(
    r"struct HardmtlsSignCtx \{",
    helpers + "\nstruct HardmtlsSignCtx {",
    content,
    count=1
)

content = re.sub(
    r"(struct HardmtlsSignCtx \{[^\}]*tbs_buffer: Vec<u8>,)",
    r"\1\n    digest_name: String,",
    content,
    count=1
)

content = re.sub(
    r"(tbs_buffer: Vec::new\(\),\n\s*\}\);)",
    r"tbs_buffer: Vec::new(),\n        digest_name: String::new(),\n    });",
    content,
    count=1
)

settable = """#[allow(unsafe_code)]
extern "C" fn signature_settable_ctx_params(
    _ctx: *const c_void,
    _provctx: *const c_void,
) -> *const openssl_sys::OSSL_PARAM {
    struct SyncP([openssl_sys::OSSL_PARAM; 3]);
    unsafe impl Sync for SyncP {}
    static PARAMS: SyncP = SyncP([
        openssl_sys::OSSL_PARAM {
            key: c"digest".as_ptr(),
            data_type: openssl_sys::OSSL_PARAM_UTF8_STRING,
            data: std::ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: c"properties".as_ptr(),
            data_type: openssl_sys::OSSL_PARAM_UTF8_STRING,
            data: std::ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: std::ptr::null(),
            data_type: 0,
            data: std::ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
    ]);
    PARAMS.0.as_ptr()
}"""

content = re.sub(
    r"extern \"C\" fn signature_settable_ctx_params\(.*?\)\s*->\s*\*const openssl_sys::OSSL_PARAM\s*\{\s*empty_param_list\(\)\s*\}",
    settable,
    content,
    flags=re.DOTALL
)

gettable = """#[allow(unsafe_code)]
extern "C" fn signature_gettable_ctx_params(
    _ctx: *const c_void,
    _provctx: *const c_void,
) -> *const openssl_sys::OSSL_PARAM {
    struct SyncP([openssl_sys::OSSL_PARAM; 2]);
    unsafe impl Sync for SyncP {}
    static PARAMS: SyncP = SyncP([
        openssl_sys::OSSL_PARAM {
            key: c"digest".as_ptr(),
            data_type: openssl_sys::OSSL_PARAM_UTF8_STRING,
            data: std::ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
        openssl_sys::OSSL_PARAM {
            key: std::ptr::null(),
            data_type: 0,
            data: std::ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        },
    ]);
    PARAMS.0.as_ptr()
}"""

content = re.sub(
    r"extern \"C\" fn signature_gettable_ctx_params\(.*?\)\s*->\s*\*const openssl_sys::OSSL_PARAM\s*\{\s*empty_param_list\(\)\s*\}",
    gettable,
    content,
    flags=re.DOTALL
)

set_params = """extern "C" fn signature_set_ctx_params(
    ctx: *mut c_void,
    params: *const openssl_sys::OSSL_PARAM,
) -> c_int {
    if ctx.is_null() || params.is_null() {
        return 1;
    }
    let sign_ctx = unsafe { &mut *ctx.cast::<HardmtlsSignCtx>() };
    
    unsafe {
        let p = openssl_sys::OSSL_PARAM_locate(params, c"digest".as_ptr());
        if let Some(digest) = get_param_utf8_string(p) {
            sign_ctx.digest_name = digest;
            log::debug!("hardmTLS provider: set digest={}", sign_ctx.digest_name);
        }
    }
    1
}"""

content = re.sub(
    r"extern \"C\" fn signature_set_ctx_params\(.*?\)\s*->\s*c_int\s*\{\s*1\s*\}",
    set_params,
    content,
    flags=re.DOTALL
)

get_params = """extern "C" fn signature_get_ctx_params(
    ctx: *mut c_void,
    params: *mut openssl_sys::OSSL_PARAM,
) -> c_int {
    if ctx.is_null() || params.is_null() {
        return 1;
    }
    let sign_ctx = unsafe { &*ctx.cast::<HardmtlsSignCtx>() };
    
    unsafe {
        let p = openssl_sys::OSSL_PARAM_locate(params, c"digest".as_ptr());
        if !p.is_null() && !sign_ctx.digest_name.is_empty() {
            set_param_utf8(&mut *p, &sign_ctx.digest_name);
        }
    }
    1
}"""

content = re.sub(
    r"extern \"C\" fn signature_get_ctx_params\(.*?\)\s*->\s*c_int\s*\{\s*// We don't provide custom params back to OpenSSL.\s*1\s*\}",
    get_params,
    content,
    flags=re.DOTALL
)

with open("src/provider.rs", "w") as f:
    f.write(content)
