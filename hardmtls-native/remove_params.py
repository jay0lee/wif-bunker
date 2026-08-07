import re

with open("src/provider.rs", "r") as f:
    content = f.read()

# For RSA
pattern = r"""    dispatch_entry!\(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, signature_get_ctx_params,
        extern "C" fn\(\*mut c_void, \*mut openssl_sys::OSSL_PARAM\) -> c_int\),
    dispatch_entry!\(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, signature_gettable_ctx_params,
        extern "C" fn\(\*const c_void, \*const c_void\) -> \*const openssl_sys::OSSL_PARAM\),
    dispatch_entry!\(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, signature_set_ctx_params,
        extern "C" fn\(\*mut c_void, \*const openssl_sys::OSSL_PARAM\) -> c_int\),
    dispatch_entry!\(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, signature_settable_ctx_params,
        extern "C" fn\(\*const c_void, \*const c_void\) -> \*const openssl_sys::OSSL_PARAM\),
"""

content = re.sub(pattern, "", content)
content = content.replace("static RSA_SIGNATURE_DISPATCH: [OsslDispatch; 17] = [", "static RSA_SIGNATURE_DISPATCH: [OsslDispatch; 13] = [")
content = content.replace("static ECDSA_SIGNATURE_DISPATCH: [OsslDispatch; 17] = [", "static ECDSA_SIGNATURE_DISPATCH: [OsslDispatch; 13] = [")

with open("src/provider.rs", "w") as f:
    f.write(content)

