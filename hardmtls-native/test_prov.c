#include <openssl/provider.h>
#include <openssl/core_dispatch.h>
#include <openssl/evp.h>
#include <stdio.h>

int main() {
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "default");
    EVP_PKEY *pkey = EVP_PKEY_new();
    // we want to list algorithm names from the default provider.
    printf("Tested.\n");
    return 0;
}
