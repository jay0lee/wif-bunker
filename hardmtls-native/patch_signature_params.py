import re

with open("src/provider.rs", "r") as f:
    content = f.read()

# Add digest_name to HardmtlsSignCtx
content = re.sub(
    r"struct HardmtlsSignCtx \{(.*?)\}",
    r"struct HardmtlsSignCtx {\1\n    digest_name: String,\n}",
    content,
    flags=re.DOTALL
)

# Initialize digest_name in signature_newctx
content = re.sub(
    r"tbs_buffer: Vec::new\(\),\n\s*\}\);",
    r"tbs_buffer: Vec::new(),\n        digest_name: String::new(),\n    });",
    content
)

# Add helper for getting UTF-8 param if not exists
# Actually we can just copy it directly into the file.
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
if "get_param_utf8_string" not in content:
    content = content.replace("struct HardmtlsSignCtx", helpers + "\nstruct HardmtlsSignCtx")

# Replace signature_settable_ctx_params
settable = """#[allow(unsafe_code)]
extern "C" fn signature_settable_ctx_params(
    _ctx: *const std::ffi::c_void,
    _provctx: *const std::ffi::c_void,
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
    r"extern \"C\" fn signature_settable_ctx_params\(.*?\)\s*->\s*\*const openssl_sys::OSSL_PARAM\s*\{.*?\}",
    settable,
    content,
    flags=re.DOTALL
)

# Replace signature_gettable_ctx_params
gettable = """#[allow(unsafe_code)]
extern "C" fn signature_gettable_ctx_params(
    _ctx: *const std::ffi::c_void,
    _provctx: *const std::ffi::c_void,
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
    r"extern \"C\" fn signature_gettable_ctx_params\(.*?\)\s*->\s*\*const openssl_sys::OSSL_PARAM\s*\{.*?\}",
    gettable,
    content,
    flags=re.DOTALL
)

# Replace signature_set_ctx_params
set_params = """#[allow(unsafe_code)]
extern "C" fn signature_set_ctx_params(
    ctx: *mut std::ffi::c_void,
    params: *const openssl_sys::OSSL_PARAM,
) -> std::ffi::c_int {
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
    r"extern \"C\" fn signature_set_ctx_params\(.*?\)\s*->\s*std::ffi::c_int\s*\{.*?\}",
    set_params,
    content,
    flags=re.DOTALL
)

# Replace signature_get_ctx_params
get_params = """#[allow(unsafe_code)]
extern "C" fn signature_get_ctx_params(
    ctx: *mut std::ffi::c_void,
    params: *mut openssl_sys::OSSL_PARAM,
) -> std::ffi::c_int {
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
    r"extern \"C\" fn signature_get_ctx_params\(.*?\)\s*->\s*std::ffi::c_int\s*\{.*?\}",
    get_params,
    content,
    flags=re.DOTALL
)

with open("src/provider.rs", "w") as f:
    f.write(content)
