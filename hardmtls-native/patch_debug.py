import re

with open("src/provider.rs", "r") as f:
    content = f.read()

# Update provider_query_operation to print algorithm names
bad_query = r"""        x if x == OSSL_OP_SIGNATURE => \{
            log::debug!\("hardmTLS provider: returning SIGNATURE algorithms"\);
            SIGNATURE_ALGORITHMS.as_ptr\(\)
        \}"""

good_query = r"""        x if x == OSSL_OP_SIGNATURE => {
            log::debug!(
                "hardmTLS provider: returning SIGNATURE algorithms (RSA: {}, ECDSA: {})",
                unsafe { std::ffi::CStr::from_ptr(SIGNATURE_ALGORITHMS[0].algorithm_names).to_string_lossy() },
                unsafe { std::ffi::CStr::from_ptr(SIGNATURE_ALGORITHMS[1].algorithm_names).to_string_lossy() }
            );
            SIGNATURE_ALGORITHMS.as_ptr()
        }"""

content = re.sub(bad_query, good_query, content)

with open("src/provider.rs", "w") as f:
    f.write(content)
