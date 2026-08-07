/*
 * DES stub implementations for OpenSSL builds with no-des.
 *
 * The rust-openssl crate (openssl-sys 0.9.x) unconditionally declares
 * extern "C" bindings for EVP_des_* functions without respecting
 * OPENSSL_NO_DES.  When linking against an OpenSSL built with no-des,
 * these symbols are missing and the linker fails (LNK1120 on Windows).
 *
 * These stubs return NULL, which is the same behavior OpenSSL uses for
 * unsupported ciphers (e.g., EVP_aes_128_cbc() returns NULL when AES
 * is disabled).  Since hardmTLS never uses DES ciphers, these stubs
 * are never called — they exist solely to satisfy the linker.
 *
 * Upstream tracking: https://github.com/sfackler/rust-openssl/issues/XXXX
 * TODO: Remove once rust-openssl adds #[cfg(not(osslconf = "OPENSSL_NO_DES"))]
 */

#include <stddef.h>  /* NULL */

/* EVP_CIPHER is opaque — we only need to return a const pointer */
typedef struct evp_cipher_st EVP_CIPHER;

const EVP_CIPHER *EVP_des_ecb(void)       { return NULL; }
const EVP_CIPHER *EVP_des_cbc(void)       { return NULL; }
const EVP_CIPHER *EVP_des_ede3(void)      { return NULL; }
const EVP_CIPHER *EVP_des_ede3_cbc(void)  { return NULL; }
const EVP_CIPHER *EVP_des_ede3_ecb(void)  { return NULL; }
const EVP_CIPHER *EVP_des_ede3_cfb64(void){ return NULL; }
const EVP_CIPHER *EVP_des_ede3_cfb8(void) { return NULL; }
const EVP_CIPHER *EVP_des_ede3_ofb(void)  { return NULL; }
