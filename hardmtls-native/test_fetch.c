#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>

int main() {
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, "ECDSA", NULL);
    if (sig) {
        printf("Fetched ECDSA: %s\n", EVP_SIGNATURE_get0_name(sig));
        EVP_SIGNATURE_free(sig);
    }
    
    sig = EVP_SIGNATURE_fetch(NULL, "ECDSA-SHA256", NULL);
    if (sig) {
        printf("Fetched ECDSA-SHA256: %s\n", EVP_SIGNATURE_get0_name(sig));
        EVP_SIGNATURE_free(sig);
    }
    return 0;
}
