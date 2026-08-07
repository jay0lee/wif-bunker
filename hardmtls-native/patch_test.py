import re

with open("tests/mtls_handshake.rs", "r") as f:
    content = f.read()

# I'll just restore the file and patch it more carefully
import subprocess
subprocess.run(["git", "checkout", "tests/mtls_handshake.rs"])

with open("tests/mtls_handshake.rs", "r") as f:
    content = f.read()

content = re.sub(
    r"struct TestPki \{(.*?)\}",
    r"struct TestPki {\1\n    client_key: openssl::pkey::PKey<openssl::pkey::Private>,\n}",
    content,
    flags=re.DOTALL
)

# Patch the first TestPki initializer
content = re.sub(
    r"client_cert_pem: client_cert\.to_pem\(\)\.unwrap\(\),\n\s*\}",
    r"client_cert_pem: client_cert.to_pem().unwrap(),\n        client_key: client_key.clone(),\n    }",
    content,
    count=1
)

# Wait, there's another TestPki initializer?
# Line 686: let pki = TestPki {
# Let's find it.
content = re.sub(
    r"let pki = TestPki \{\n(.*?)\n\s*client_cert_pem: client_cert_pem\.to_vec\(\),\n\s*\}\;",
    r"let pki = TestPki {\n\1\n        client_cert_pem: client_cert_pem.to_vec(),\n        client_key: client_key.clone(),\n    };",
    content,
    flags=re.DOTALL
)

# And now patch dummy_sign for both tests.
good_dummy = r"""    let client_key = pki.client_key.clone();
    let dummy_sign = Box::new(move |tbs: &[u8]| -> Result<Vec<u8>, ()> {
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &client_key).unwrap();
        signer.update(tbs).unwrap();
        let sig = signer.sign_to_vec().unwrap();
        
        // Also increment the global counter so the assert at the end passes
        SIGN_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        Ok(sig)
    });"""

content = re.sub(
    r"    let dummy_sign = Box::new\(\|tbs: &\[u8\]\| -> Result<Vec<u8>, \(\)> \{.*?\}\);",
    good_dummy,
    content,
    flags=re.DOTALL
)

with open("tests/mtls_handshake.rs", "w") as f:
    f.write(content)

