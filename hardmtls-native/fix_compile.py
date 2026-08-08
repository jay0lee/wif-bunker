import re

with open("src/provider.rs") as f:
    content = f.read()

content = re.sub(
    r"tbs_buffer: orig\.tbs_buffer\.clone\(\),\n\s*\}\);",
    r"tbs_buffer: orig.tbs_buffer.clone(),\n        digest_name: orig.digest_name.clone(),\n    });",
    content,
    flags=re.DOTALL,
)

with open("src/provider.rs", "w") as f:
    f.write(content)
