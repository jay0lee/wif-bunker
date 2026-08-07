//! Build script for hardmTLS.
//!
//! Detects whether the target OpenSSL was built with `no-des` and, if so,
//! compiles stub implementations of the DES cipher functions.
//!
//! **Why this is needed:**
//! The `openssl-sys` crate (v0.9.x) unconditionally declares `extern "C"`
//! bindings for `EVP_des_*` functions without gating them behind
//! `#[cfg(not(osslconf = "OPENSSL_NO_DES"))]`.  When linking against an
//! OpenSSL library built with the `no-des` flag, these symbols don't exist
//! and the linker fails (LNK1120 on Windows, undefined symbol on Linux).
//!
//! The stubs return `NULL`, matching OpenSSL's own pattern for ciphers that
//! are unavailable.  hardmTLS never uses DES ciphers, so the stubs are
//! never called at runtime.

use std::path::{Path, PathBuf};

fn main() {
    // Locate the OpenSSL include directory.
    // openssl-sys sets DEP_OPENSSL_INCLUDE after it runs, but build scripts
    // for the *same* crate can't read DEP_ vars.  So we check the same env
    // vars that openssl-sys uses (OPENSSL_DIR, OPENSSL_INCLUDE_DIR).
    let include_dir = std::env::var("OPENSSL_INCLUDE_DIR")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            std::env::var("OPENSSL_DIR")
                .ok()
                .map(|d| PathBuf::from(d).join("include"))
        });

    let has_no_des = include_dir
        .as_ref()
        .is_some_and(|dir| header_defines_no_des(dir));

    if has_no_des {
        println!("cargo:warning=OpenSSL built with no-des — compiling DES stubs");
        cc::Build::new()
            .file("build_support/des_stubs.c")
            .compile("des_stubs");
    }
}

/// Check whether the OpenSSL headers define `OPENSSL_NO_DES`.
///
/// Reads `opensslconf.h` (OpenSSL 1.x) or `configuration.h` (OpenSSL 3.x+)
/// and looks for the `#define OPENSSL_NO_DES` line.
fn header_defines_no_des(include_dir: &Path) -> bool {
    // OpenSSL 3.x moved config defines into configuration.h
    // (opensslconf.h still exists but just #includes configuration.h)
    let candidates = [
        include_dir.join("openssl/configuration.h"),
        include_dir.join("openssl/opensslconf.h"),
    ];

    for path in &candidates {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if contents.contains("OPENSSL_NO_DES") {
                return true;
            }
        }
    }

    false
}
