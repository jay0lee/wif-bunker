import re

with open("src/provider.rs", "r") as f:
    content = f.read()

bad_rsa = r'algorithm_names: c"RSA:rsaEncryption:RSA-PSS:RSASSA-PSS"\.as_ptr\(\)'
good_rsa = r'algorithm_names: c"RSA:rsaEncryption:1.2.840.113549.1.1.1:RSA-SHA256:RSA-SHA384:RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10".as_ptr()'

bad_ecdsa = r'algorithm_names: c"ECDSA"\.as_ptr\(\)'
good_ecdsa = r'algorithm_names: c"ECDSA:id-ecPublicKey:1.2.840.10045.2.1:ECDSA-SHA256:ECDSA-SHA384".as_ptr()'

content = re.sub(bad_rsa, good_rsa, content)
content = re.sub(bad_ecdsa, good_ecdsa, content)

with open("src/provider.rs", "w") as f:
    f.write(content)
