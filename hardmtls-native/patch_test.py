import re

with open("tests/mtls_handshake.rs", "r") as f:
    content = f.read()

# Make the server require a specific client CA that is NOT our dummy CA
replacement = """    let mut server_ctx = SslContext::builder(SslMethod::tls()).unwrap();
    server_ctx.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    
    // Create a dummy CA to request
    let dummy_ca = openssl::x509::X509NameBuilder::new().unwrap();
    dummy_ca.append_entry_by_text("CN", "Bogus Server CA").unwrap();
    server_ctx.add_client_ca(&dummy_ca.build());"""

content = content.replace("    let mut server_ctx = SslContext::builder(SslMethod::tls()).unwrap();\n    server_ctx.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);", replacement)

with open("tests/mtls_handshake.rs", "w") as f:
    f.write(content)
