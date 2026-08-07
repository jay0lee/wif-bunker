import re

with open("src/provider.rs", "r") as f:
    content = f.read()

# Replace SIGNATURE_ALGORITHMS ECDSA string
content = re.sub(
    r'algorithm_names: c"ECDSA.*?".as_ptr\(\),',
    r'algorithm_names: c"ECDSA".as_ptr(),',
    content
)

# For RSA, just use "RSA" to avoid namemap conflicts with RSASSA-PSS etc
content = re.sub(
    r'algorithm_names: c"RSA.*?".as_ptr\(\),',
    r'algorithm_names: c"RSA".as_ptr(),',
    content
)

with open("src/provider.rs", "w") as f:
    f.write(content)
