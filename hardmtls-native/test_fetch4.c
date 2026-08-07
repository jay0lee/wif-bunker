#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>

int main() {
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, "NONEXISTENT", NULL);
    if (!sig) {
        ERR_print_errors_fp(stdout);
    }
    return 0;
}
