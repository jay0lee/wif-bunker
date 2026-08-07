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

static const OSSL_DISPATCH my_sig_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))my_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))my_freectx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))my_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))my_sign },
    { 0, NULL }
};

static const OSSL_ALGORITHM my_sigs[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1:RSA-SHA256:RSA-SHA384:RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10", "provider=myprov", my_sig_fns, "My RSA" },
    { "ECDSA:id-ecPublicKey:1.2.840.10045.2.1:ECDSA-SHA256:ECDSA-SHA384", "provider=myprov", my_sig_fns, "My ECDSA" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *my_query(void *provctx, int operation_id, int *no_cache) {
    *no_cache = 0;
    if (operation_id == OSSL_OP_SIGNATURE) return my_sigs;
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
    OSSL_PROVIDER_add_builtin(NULL, "myprov", my_provider_init);
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "myprov");
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, "ECDSA", "provider=myprov");
    if (sig) {
        printf("Fetch succeeded\n");
    } else {
        printf("Fetch failed\n");
        ERR_print_errors_fp(stdout);
    }
    return 0;
}
