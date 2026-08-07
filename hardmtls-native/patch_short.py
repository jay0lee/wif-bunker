import re

with open("src/provider.rs", "r") as f:
    content = f.read()

# Replace SIGNATURE_ALGORITHMS ECDSA string
old_ec_sig = r'algorithm_names: c"ECDSA:id-ecPublicKey:1.2.840.10045.2.1:ECDSA-SHA256:ECDSA-SHA384".as_ptr(),'
new_ec_sig = r'algorithm_names: c"ECDSA:id-ecPublicKey".as_ptr(),'

content = content.replace(old_ec_sig, new_ec_sig)

with open("src/provider.rs", "w") as f:
    f.write(content)

