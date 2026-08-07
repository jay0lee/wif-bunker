import re

with open("src/provider.rs", "r") as f:
    content = f.read()

# Replace KEYMGMT_ALGORITHMS
old_rsa_key = r'algorithm_names: c"RSA".as_ptr(),'
new_rsa_key = r'algorithm_names: c"RSA:rsaEncryption:1.2.840.113549.1.1.1".as_ptr(),'

old_ec_key = r'algorithm_names: c"EC".as_ptr(),'
new_ec_key = r'algorithm_names: c"EC:id-ecPublicKey:1.2.840.10045.2.1".as_ptr(),'

content = content.replace(old_rsa_key, new_rsa_key)
content = content.replace(old_ec_key, new_ec_key)

# Replace SIGNATURE_ALGORITHMS
old_rsa_sig = r'algorithm_names: c"RSA:rsaEncryption:RSA-SHA256:RSA-SHA384:RSA-PSS:RSASSA-PSS".as_ptr(),'
new_rsa_sig = r'algorithm_names: c"RSA:rsaEncryption:1.2.840.113549.1.1.1:RSA-SHA256:RSA-SHA384:RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10".as_ptr(),'

old_ec_sig = r'algorithm_names: c"ECDSA:ECDSA-SHA256:ECDSA-SHA384".as_ptr(),'
new_ec_sig = r'algorithm_names: c"ECDSA:id-ecPublicKey:1.2.840.10045.2.1:ECDSA-SHA256:ECDSA-SHA384".as_ptr(),'

content = content.replace(old_rsa_sig, new_rsa_sig)
content = content.replace(old_ec_sig, new_ec_sig)

with open("src/provider.rs", "w") as f:
    f.write(content)

