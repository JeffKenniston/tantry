with open("crates/data/src/crypto.rs", "r") as f:
    content = f.read()
import re
enum_def = """
pub enum AeadCipherSuite {
    XChaCha20Poly1305,
    Aes256GcmSiv,
}
"""
content = re.sub(r'pub fn compute_canonical_aad', enum_def + "\npub fn compute_canonical_aad", content)
with open("crates/data/src/crypto.rs", "w") as f:
    f.write(content)
