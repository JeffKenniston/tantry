with open("crates/cognitive/src/semantic_cache.rs", "r") as f:
    content = f.read()
import re
content = re.sub(r'\.lock\(\)\.unwrap\(\)', '.lock()', content)
with open("crates/cognitive/src/semantic_cache.rs", "w") as f:
    f.write(content)
