#include <openssl/provider.h>
#include <openssl/evp.h>
#include <stdio.h>

int main() {
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, "ECDSA", NULL);
    if (sig) {
        printf("Found ECDSA\n");
        EVP_SIGNATURE_free(sig);
    } else {
        printf("Could not find ECDSA\n");
    }
    return 0;
}
