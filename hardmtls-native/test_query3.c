#include <openssl/provider.h>
#include <openssl/core_dispatch.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>

void* my_newctx(void *provctx, const char *propq) { return (void*)1; }
void my_freectx(void *ctx) {}
int my_init(void *ctx, void *provkey, const OSSL_PARAM params[]) { return 1; }
int my_sign(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize,
            const unsigned char *tbs, size_t tbslen) { return 1; }

void* my_km_new(void *provctx) { return (void*)1; }
void my_km_free(void *keydata) {}
int my_km_has(const void *keydata, int selection) { return 1; }
int my_km_match(const void *keydata1, const void *keydata2, int selection) { return 1; }
int my_km_import(void *keydata, int selection, const OSSL_PARAM params[]) { return 1; }
const OSSL_PARAM* my_km_import_types(int selection) { return NULL; }

static const OSSL_DISPATCH my_km_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))my_km_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))my_km_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))my_km_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))my_km_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))my_km_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))my_km_import_types },
    { 0, NULL }
};

static const OSSL_DISPATCH my_sig_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))my_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))my_freectx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))my_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))my_sign },
    { 0, NULL }
};

static const OSSL_ALGORITHM my_sigs[] = {
    { "ECDSA", "provider=myprov", my_sig_fns, "My ECDSA" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM my_kms[] = {
    { "EC", "provider=myprov", my_km_fns, "My EC" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *my_query(void *provctx, int operation_id, int *no_cache) {
    *no_cache = 0;
    if (operation_id == OSSL_OP_SIGNATURE) return my_sigs;
    if (operation_id == OSSL_OP_KEYMGMT) return my_kms;
    return NULL;
}

static const OSSL_DISPATCH my_prov_fns[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))my_query },
    { 0, NULL }
};

int my_provider_init(const OSSL_CORE_HANDLE *handle,
                     const OSSL_DISPATCH *in,
                     const OSSL_DISPATCH **out,
                     void **provctx) {
    *out = my_prov_fns;
    *provctx = (void*)1;
    return 1;
}

int main() {
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_add_builtin(NULL, "myprov", my_provider_init);
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "myprov");
    
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int rc = EVP_DigestSignInit_ex(mctx, NULL, "SHA256", NULL, "provider=myprov", pkey, NULL);
    if (rc != 1) {
        printf("EVP_DigestSignInit failed\n");
        ERR_print_errors_fp(stdout);
    } else {
        printf("EVP_DigestSignInit succeeded\n");
    }
    
    return 0;
}
