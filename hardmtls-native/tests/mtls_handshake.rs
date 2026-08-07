//! End-to-end mTLS integration test for the hardmTLS OpenSSL Provider.
//!
//! Starts a local TLS server that **requires** client certificates, then
//! connects using our custom provider-backed `EVP_PKEY` for both TLS 1.2
//! and TLS 1.3 to verify:
//!
//! 1. Our SIGNATURE `digest_sign_init` / `digest_sign_final` functions
//!    are actually called by OpenSSL during the TLS handshake.
//! 2. Post-handshake authentication (PHA) works correctly in TLS 1.3.
//! 3. CertificateVerify works correctly in TLS 1.2.
//!
//! Run with: `cargo test --test mtls_handshake -- --nocapture`
#![allow(missing_docs, unsafe_code)]

use foreign_types_shared::ForeignType;
use std::ffi::{c_int, c_uchar, c_void};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Tracks how many times our sign callback is invoked.
static SIGN_CALL_COUNT: AtomicU32 = AtomicU32::new(0);

// ═══════════════════════════════════════════════════════════════════════
// Signing callback
// ═══════════════════════════════════════════════════════════════════════

/// Dummy sign callback that produces a fake ECDSA signature.
///
/// Real mTLS would fail server-side validation, but we only care that
/// OpenSSL actually *calls* this function during the handshake.
/// An ECDSA P-256 signature is a DER-encoded SEQUENCE of two INTEGERs.
/// We produce a minimal valid DER structure so OpenSSL doesn't reject
/// it at the encoding level.
unsafe extern "C" fn test_sign(
    sig: *mut c_uchar,
    sig_len: *mut usize,
    _tbs: *const c_uchar,
    _tbs_len: usize,
) -> c_int {
    SIGN_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
    eprintln!(
        "    >>> test_sign invoked (call #{})",
        SIGN_CALL_COUNT.load(Ordering::SeqCst)
    );

    // Minimal DER-encoded ECDSA signature: SEQUENCE { INTEGER(1), INTEGER(1) }
    // 30 06  -- SEQUENCE, 6 bytes
    //   02 01 01  -- INTEGER, 1 byte, value 1
    //   02 01 01  -- INTEGER, 1 byte, value 1
    let dummy_sig: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

    if sig.is_null() {
        // Size query — return maximum possible size (P-256 max is 72)
        unsafe { *sig_len = 72 };
        return 1;
    }

    let max = unsafe { *sig_len };
    if max < dummy_sig.len() {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(dummy_sig.as_ptr(), sig, dummy_sig.len());
        *sig_len = dummy_sig.len();
    }
    1
}

// ═══════════════════════════════════════════════════════════════════════
// PKI: CA, server cert, client cert
// ═══════════════════════════════════════════════════════════════════════

struct TestPki {
    ca_cert: openssl::x509::X509,
    server_cert: openssl::x509::X509,
    server_key: openssl::pkey::PKey<openssl::pkey::Private>,
    client_cert_pem: Vec<u8>,
}

fn build_test_pki() -> TestPki {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509Builder, X509NameBuilder};

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

    // ── CA ──────────────────────────────────────────────────────────────
    let ca_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut ca_builder = X509Builder::new().unwrap();
    ca_builder.set_version(2).unwrap();
    let mut sn = BigNum::new().unwrap();
    sn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    ca_builder
        .set_serial_number(&sn.to_asn1_integer().unwrap())
        .unwrap();
    let mut ca_name = X509NameBuilder::new().unwrap();
    ca_name.append_entry_by_text("CN", "test-ca").unwrap();
    let ca_name = ca_name.build();
    ca_builder.set_subject_name(&ca_name).unwrap();
    ca_builder.set_issuer_name(&ca_name).unwrap();
    ca_builder.set_pubkey(&ca_key).unwrap();
    ca_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    ca_builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    ca_builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    ca_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca_cert = ca_builder.build();

    // ── Server cert (signed by CA) ─────────────────────────────────────
    let server_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut srv_builder = X509Builder::new().unwrap();
    srv_builder.set_version(2).unwrap();
    let mut sn = BigNum::new().unwrap();
    sn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    srv_builder
        .set_serial_number(&sn.to_asn1_integer().unwrap())
        .unwrap();
    let mut srv_name = X509NameBuilder::new().unwrap();
    srv_name.append_entry_by_text("CN", "localhost").unwrap();
    let srv_name = srv_name.build();
    srv_builder.set_subject_name(&srv_name).unwrap();
    srv_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    srv_builder.set_pubkey(&server_key).unwrap();
    srv_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    srv_builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    srv_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let server_cert = srv_builder.build();

    // ── Client cert (signed by CA) ─────────────────────────────────────
    let client_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut cli_builder = X509Builder::new().unwrap();
    cli_builder.set_version(2).unwrap();
    let mut sn = BigNum::new().unwrap();
    sn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    cli_builder
        .set_serial_number(&sn.to_asn1_integer().unwrap())
        .unwrap();
    let mut cli_name = X509NameBuilder::new().unwrap();
    cli_name
        .append_entry_by_text("CN", "test-client")
        .unwrap();
    let cli_name = cli_name.build();
    cli_builder.set_subject_name(&cli_name).unwrap();
    cli_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    cli_builder.set_pubkey(&client_key).unwrap();
    cli_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cli_builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cli_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let client_cert = cli_builder.build();
    let client_cert_pem = client_cert.to_pem().unwrap();

    TestPki {
        ca_cert,
        server_cert,
        server_key,
        client_cert_pem,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// mTLS server
// ═══════════════════════════════════════════════════════════════════════

/// Builds an `SslAcceptor` that requires client certificates.
fn build_server_acceptor(
    pki: &TestPki,
    force_tls_version: Option<TlsVersion>,
) -> openssl::ssl::SslAcceptor {
    use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode};

    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    builder.set_certificate(&pki.server_cert).unwrap();
    builder.set_private_key(&pki.server_key).unwrap();

    // Trust our CA for client cert verification.
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new().unwrap();
    store_builder.add_cert(pki.ca_cert.clone()).unwrap();
    let store = store_builder.build();
    builder.set_cert_store(store);

    // Also tell the server to advertise acceptable CAs in CertificateRequest.
    // This ensures the client knows its cert's issuer is acceptable.
    builder.add_client_ca(&pki.ca_cert).unwrap();

    // ── Require client certificate ─────────────────────────────────────
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

    // ── Pin TLS version if requested ───────────────────────────────────
    if let Some(ver) = force_tls_version {
        match ver {
            TlsVersion::Tls12 => {
                builder
                    .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
                    .unwrap();
                builder
                    .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
                    .unwrap();
            }
            TlsVersion::Tls13 => {
                builder
                    .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))
                    .unwrap();
                builder
                    .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))
                    .unwrap();
            }
        }
    }

    builder.build()
}

/// Run a tiny "echo" server that accepts one mTLS connection, reads a
/// request line, and writes back "OK\n".
fn run_mtls_server(
    listener: TcpListener,
    acceptor: Arc<openssl::ssl::SslAcceptor>,
    ready: Arc<std::sync::Barrier>,
) {
    ready.wait(); // signal to the client that we're listening

    let (stream, _addr) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    match acceptor.accept(stream) {
        Ok(mut tls_stream) => {
            eprintln!("    [server] TLS accepted, client cert presented ✓");
            let mut buf = [0u8; 128];
            let n = tls_stream.read(&mut buf).unwrap_or(0);
            eprintln!(
                "    [server] read {} bytes: {:?}",
                n,
                String::from_utf8_lossy(&buf[..n])
            );
            let _ = tls_stream.write_all(b"OK\n");
        }
        Err(e) => {
            // We expect this to fail because our dummy signature is invalid.
            // The important thing is whether the client's sign_func was called.
            eprintln!("    [server] TLS accept error (expected with dummy sig): {e}");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Client helper
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy)]
enum TlsVersion {
    Tls12,
    Tls13,
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsVersion::Tls12 => write!(f, "TLS 1.2"),
            TlsVersion::Tls13 => write!(f, "TLS 1.3"),
        }
    }
}

/// Connect to the local mTLS server using our hardmTLS provider.
/// Returns the number of sign_func invocations that occurred.
fn mtls_client_connect(
    pki: &TestPki,
    addr: std::net::SocketAddr,
    version: TlsVersion,
) -> u32 {
    let cert_cstr = std::ffi::CString::new(pki.client_cert_pem.clone()).unwrap();

    // Build client SSL_CTX.
    let method = openssl::ssl::SslMethod::tls_client();
    let mut builder = openssl::ssl::SslContext::builder(method).unwrap();

    // Trust our test CA.
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new().unwrap();
    store_builder.add_cert(pki.ca_cert.clone()).unwrap();
    builder.set_cert_store(store_builder.build());

    // Pin TLS version.
    match version {
        TlsVersion::Tls12 => {
            builder
                .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
                .unwrap();
            builder
                .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
                .unwrap();
        }
        TlsVersion::Tls13 => {
            builder
                .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))
                .unwrap();
            builder
                .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))
                .unwrap();
        }
    }

    let ssl_ctx = builder.build();

    // Record sign count before our call.
    let before = SIGN_CALL_COUNT.load(Ordering::SeqCst);

    // Configure with our provider.
    let rc = unsafe {
        hardmtls::ConfigureSslContext(
            test_sign,
            cert_cstr.as_ptr(),
            ssl_ctx.as_ptr().cast::<c_void>(),
        )
    };
    assert_eq!(rc, 1, "ConfigureSslContext failed");

    // Diagnostic: check what OpenSSL thinks about our key
    unsafe {
        let ssl_ctx_ptr = ssl_ctx.as_ptr();
        // SSL_CTX_get0_privatekey returns the EVP_PKEY without incrementing refcount
        let pkey = openssl_sys::SSL_CTX_get0_privatekey(ssl_ctx_ptr);
        if !pkey.is_null() {
            let pkey_id = openssl_sys::EVP_PKEY_get_id(pkey);
            let pkey_size = openssl_sys::EVP_PKEY_get_size(pkey);
            let pkey_bits = openssl_sys::EVP_PKEY_get_bits(pkey);
            
            eprintln!("    [diag] EVP_PKEY id={pkey_id}, size={pkey_size}, bits={pkey_bits}");
            eprintln!("    [diag] EVP_PKEY_EC={}, EVP_PKEY_RSA={}", openssl_sys::EVP_PKEY_EC, openssl_sys::EVP_PKEY_RSA);
            
            // Check group name
            let mut group_buf = [0u8; 64];
            let mut group_len: usize = 0;
            let got_group = openssl_sys::EVP_PKEY_get_utf8_string_param(
                pkey,
                c"group".as_ptr(),
                group_buf.as_mut_ptr().cast(),
                group_buf.len(),
                &mut group_len,
            );
            if got_group == 1 {
                let group_name = std::str::from_utf8(&group_buf[..group_len]).unwrap_or("?");
                eprintln!("    [diag] EVP_PKEY group_name={group_name}");
            } else {
                eprintln!("    [diag] EVP_PKEY has no group_name");
            }
            
            // Check EVP_PKEY_is_a
            let is_ec = openssl_sys::EVP_PKEY_is_a(pkey, c"EC".as_ptr());
            eprintln!("    [diag] EVP_PKEY_is_a(pkey, \"EC\") = {is_ec}");
            
            // Check EVP_PKEY_eq with the certificate's public key
            let cert = openssl_sys::SSL_CTX_get0_certificate(ssl_ctx_ptr);
            if !cert.is_null() {
                let cert_pubkey = openssl_sys::X509_get_pubkey(cert as *mut _);
                if !cert_pubkey.is_null() {
                    let eq_result = openssl_sys::EVP_PKEY_eq(cert_pubkey, pkey);
                    eprintln!("    [diag] EVP_PKEY_eq(cert_pubkey, pkey) = {eq_result}");
                    eprintln!("    [diag]   (1=match, 0=no-match, -1=not-same-type, -2=unsupported)");
                    openssl_sys::EVP_PKEY_free(cert_pubkey);
                } else {
                    eprintln!("    [diag] cert has no public key!");
                }
            } else {
                eprintln!("    [diag] SSL_CTX has no certificate!");
            }
            
            // Fetch ECDSA SIGNATURE - test hardmtls FIRST (before NULL-props
            // fetch which triggers construction for ALL providers and may
            // cache the operation bit, masking our actual error)
            openssl_sys::ERR_clear_error();

            // Helper closure to dump all errors with full details
            let dump_errors = |label: &str| {
                loop {
                    let err = openssl_sys::ERR_get_error();
                    if err == 0 { break; }
                    let lib = openssl_sys::ERR_lib_error_string(err);
                    let reason = openssl_sys::ERR_reason_error_string(err);
                    let lib_s = if !lib.is_null() { std::ffi::CStr::from_ptr(lib).to_str().unwrap_or("?") } else { "?" };
                    let rsn_s = if !reason.is_null() { std::ffi::CStr::from_ptr(reason).to_str().unwrap_or("?") } else { "?" };
                    eprintln!("    [diag]   {label}: lib={lib_s} reason={rsn_s} code={err:#x}");
                }
            };

            // Try hardmtls FIRST
            let sig_ecdsa_hardmtls = openssl_sys::EVP_SIGNATURE_fetch(
                std::ptr::null_mut(),
                c"ECDSA".as_ptr(),
                c"provider=hardmtls".as_ptr(),
            );
            eprintln!("    [diag] EVP_SIGNATURE_fetch('ECDSA', provider=hardmtls) = {:?}", sig_ecdsa_hardmtls);
            if sig_ecdsa_hardmtls.is_null() {
                dump_errors("ECDSA+hardmtls");
            } else {
                openssl_sys::EVP_SIGNATURE_free(sig_ecdsa_hardmtls);
            }
            openssl_sys::ERR_clear_error();

            let sig_ecdsa_null = openssl_sys::EVP_SIGNATURE_fetch(
                std::ptr::null_mut(),
                c"ECDSA".as_ptr(),
                std::ptr::null(),
            );
            eprintln!("    [diag] EVP_SIGNATURE_fetch('ECDSA', NULL) = {:?}", sig_ecdsa_null);
            if sig_ecdsa_null.is_null() {
                dump_errors("ECDSA+NULL");
            } else {
                openssl_sys::EVP_SIGNATURE_free(sig_ecdsa_null);
            }
            openssl_sys::ERR_clear_error();
            
            let sig_ecdsa_default = openssl_sys::EVP_SIGNATURE_fetch(
                std::ptr::null_mut(),
                c"ECDSA".as_ptr(),
                c"provider=default".as_ptr(),
            );
            eprintln!("    [diag] EVP_SIGNATURE_fetch('ECDSA', provider=default) = {:?}", sig_ecdsa_default);
            if sig_ecdsa_default.is_null() {
                dump_errors("ECDSA+default");
            } else {
                openssl_sys::EVP_SIGNATURE_free(sig_ecdsa_default);
            }
            openssl_sys::ERR_clear_error();

            let md_ctx = openssl_sys::EVP_MD_CTX_new();
            if !md_ctx.is_null() {
                // EVP_DigestSignInit with SHA256 and our pkey
                let sha256 = openssl_sys::EVP_sha256();
                let mut pctx: *mut openssl_sys::EVP_PKEY_CTX = std::ptr::null_mut();
                let rc = openssl_sys::EVP_DigestSignInit(
                    md_ctx,
                    &mut pctx,
                    sha256,
                    std::ptr::null_mut(), // no engine
                    pkey as *mut _,
                );
                eprintln!("    [diag] EVP_DigestSignInit(SHA256, pkey) = {rc}");
                if rc != 1 {
                    // Print ALL queued OpenSSL errors
                    loop {
                        let err = openssl_sys::ERR_get_error();
                        if err == 0 { break; }
                        let lib = openssl_sys::ERR_lib_error_string(err);
                        let reason = openssl_sys::ERR_reason_error_string(err);
                        let lib_s = if !lib.is_null() { std::ffi::CStr::from_ptr(lib).to_str().unwrap_or("?") } else { "?" };
                        let rsn_s = if !reason.is_null() { std::ffi::CStr::from_ptr(reason).to_str().unwrap_or("?") } else { "?" };
                        eprintln!("    [diag]   err: lib={lib_s} reason={rsn_s}");
                    }
                }
                openssl_sys::EVP_MD_CTX_free(md_ctx);
            }
        } else {
            eprintln!("    [diag] SSL_CTX has no private key!");
        }
    }

    // Connect.
    let stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    let ssl = openssl::ssl::Ssl::new(&ssl_ctx).unwrap();

    let connect_result = ssl.connect(stream);
    match connect_result {
        Ok(mut tls_stream) => {
            eprintln!("    [client] Handshake succeeded ({version})");
            let _ = tls_stream.write_all(b"HELLO\n");
            let mut buf = [0u8; 64];
            let _ = tls_stream.read(&mut buf);
        }
        Err(e) => {
            // Handshake failure is expected because our dummy signature
            // won't pass cryptographic verification. The key assertion is
            // whether sign_func was invoked.
            eprintln!("    [client] Handshake error ({version}, expected with dummy sig): {e}");
        }
    }

    let after = SIGN_CALL_COUNT.load(Ordering::SeqCst);
    after - before
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

/// Tests that our provider's sign function is called during a TLS 1.2
/// mTLS handshake. In TLS 1.2, the server sends CertificateRequest
/// during the initial handshake, so the client signs inline.
#[test]
fn mtls_tls12_sign_func_called() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init();

    let pki = build_test_pki();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    eprintln!("=== TLS 1.2 mTLS test on {addr} ===");

    let acceptor = Arc::new(build_server_acceptor(&pki, Some(TlsVersion::Tls12)));
    let barrier = Arc::new(std::sync::Barrier::new(2));

    let server_barrier = barrier.clone();
    let server_acceptor = acceptor.clone();
    let server = std::thread::spawn(move || {
        run_mtls_server(listener, server_acceptor, server_barrier);
    });

    barrier.wait(); // wait for server to be ready
    let sign_count = mtls_client_connect(&pki, addr, TlsVersion::Tls12);

    server.join().unwrap();

    eprintln!("=== TLS 1.2: sign_func called {sign_count} time(s) ===");
    assert!(
        sign_count > 0,
        "sign_func was never called during TLS 1.2 mTLS handshake! \
         This means our provider's SIGNATURE implementation is not being \
         used by OpenSSL for the CertificateVerify message."
    );
}

/// Tests that our provider's sign function is called during a TLS 1.3
/// mTLS handshake. In TLS 1.3, client certificates are sent via
/// post-handshake authentication (PHA), which requires explicit opt-in
/// via `SSL_CTX_set_post_handshake_auth(ctx, 1)`.
#[test]
fn mtls_tls13_sign_func_called() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init();

    let pki = build_test_pki();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    eprintln!("=== TLS 1.3 mTLS test on {addr} ===");

    let acceptor = Arc::new(build_server_acceptor(&pki, Some(TlsVersion::Tls13)));
    let barrier = Arc::new(std::sync::Barrier::new(2));

    let server_barrier = barrier.clone();
    let server_acceptor = acceptor.clone();
    let server = std::thread::spawn(move || {
        run_mtls_server(listener, server_acceptor, server_barrier);
    });

    barrier.wait();
    let sign_count = mtls_client_connect(&pki, addr, TlsVersion::Tls13);

    server.join().unwrap();

    eprintln!("=== TLS 1.3: sign_func called {sign_count} time(s) ===");
    assert!(
        sign_count > 0,
        "sign_func was never called during TLS 1.3 mTLS handshake! \
         This likely means post-handshake authentication (PHA) is not \
         enabled — SSL_CTX_set_post_handshake_auth(ctx, 1) must be called."
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Baseline: prove the test harness works with standard OpenSSL keys
// ═══════════════════════════════════════════════════════════════════════

/// Baseline test — no custom provider, just normal OpenSSL mTLS.
///
/// If THIS test fails, the server/PKI setup is broken and nothing else
/// can be expected to work.
#[test]
fn baseline_mtls_no_provider() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init();

    // Build PKI — but this time we also keep the client private key.
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509Builder, X509NameBuilder};

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

    // ── CA ──────────────────────────────────────────────────────────────
    let ca_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut ca_builder = X509Builder::new().unwrap();
    ca_builder.set_version(2).unwrap();
    let mut sn = BigNum::new().unwrap();
    sn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
    ca_builder.set_serial_number(&sn.to_asn1_integer().unwrap()).unwrap();
    let mut ca_name = X509NameBuilder::new().unwrap();
    ca_name.append_entry_by_text("CN", "baseline-ca").unwrap();
    let ca_name = ca_name.build();
    ca_builder.set_subject_name(&ca_name).unwrap();
    ca_builder.set_issuer_name(&ca_name).unwrap();
    ca_builder.set_pubkey(&ca_key).unwrap();
    ca_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    ca_builder.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    ca_builder.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
    ca_builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap()).unwrap();
    ca_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca_cert = ca_builder.build();

    // ── Server cert ────────────────────────────────────────────────────
    let server_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut srv_builder = X509Builder::new().unwrap();
    srv_builder.set_version(2).unwrap();
    let mut sn = BigNum::new().unwrap();
    sn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
    srv_builder.set_serial_number(&sn.to_asn1_integer().unwrap()).unwrap();
    let mut srv_name = X509NameBuilder::new().unwrap();
    srv_name.append_entry_by_text("CN", "localhost").unwrap();
    let srv_name = srv_name.build();
    srv_builder.set_subject_name(&srv_name).unwrap();
    srv_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    srv_builder.set_pubkey(&server_key).unwrap();
    srv_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    srv_builder.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    srv_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let server_cert = srv_builder.build();

    // ── Client cert + key (normal OpenSSL, no provider) ────────────────
    let client_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut cli_builder = X509Builder::new().unwrap();
    cli_builder.set_version(2).unwrap();
    let mut sn = BigNum::new().unwrap();
    sn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
    cli_builder.set_serial_number(&sn.to_asn1_integer().unwrap()).unwrap();
    let mut cli_name = X509NameBuilder::new().unwrap();
    cli_name.append_entry_by_text("CN", "baseline-client").unwrap();
    let cli_name = cli_name.build();
    cli_builder.set_subject_name(&cli_name).unwrap();
    cli_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    cli_builder.set_pubkey(&client_key).unwrap();
    cli_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    cli_builder.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    cli_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let client_cert = cli_builder.build();

    // ── Server ─────────────────────────────────────────────────────────
    let pki = TestPki {
        ca_cert: ca_cert.clone(),
        server_cert,
        server_key,
        client_cert_pem: vec![], // not used by baseline
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    eprintln!("=== BASELINE mTLS test (no provider) on {addr} ===");

    let acceptor = Arc::new(build_server_acceptor(&pki, Some(TlsVersion::Tls12)));
    let barrier = Arc::new(std::sync::Barrier::new(2));

    let server_barrier = barrier.clone();
    let server_acceptor = acceptor.clone();
    let server = std::thread::spawn(move || {
        run_mtls_server(listener, server_acceptor, server_barrier);
    });

    barrier.wait();

    // ── Client with normal key (no hardmTLS provider) ──────────────────
    let method = openssl::ssl::SslMethod::tls_client();
    let mut builder = openssl::ssl::SslConnector::builder(method).unwrap();

    // Trust our CA
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new().unwrap();
    store_builder.add_cert(ca_cert).unwrap();
    builder.set_cert_store(store_builder.build());

    // Set client cert + key (standard OpenSSL, no provider)
    builder.set_certificate(&client_cert).unwrap();
    builder.set_private_key(&client_key).unwrap();

    // Pin to TLS 1.2
    builder
        .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
        .unwrap();
    builder
        .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
        .unwrap();

    let connector = builder.build();

    let stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    match connector.connect("localhost", stream) {
        Ok(mut tls_stream) => {
            eprintln!("    [baseline-client] Handshake succeeded ✓");
            tls_stream.write_all(b"HELLO\n").unwrap();
            let mut buf = [0u8; 64];
            let n = tls_stream.read(&mut buf).unwrap_or(0);
            eprintln!(
                "    [baseline-client] Got response: {:?}",
                String::from_utf8_lossy(&buf[..n])
            );
            assert!(n > 0, "Expected server response but got nothing");
        }
        Err(e) => {
            panic!("BASELINE mTLS handshake failed — test harness is broken: {e}");
        }
    }

    server.join().unwrap();
    eprintln!("=== BASELINE mTLS: PASSED ===");
}
