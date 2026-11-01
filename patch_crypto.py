import sys

content = open('crates/data/src/crypto.rs', 'r').read()

new_functions = """

pub fn build_checkpoint_aad(thread_id: &str, checkpoint_id: &str, step_index: u64, key_epoch: u32) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"tantry:checkpoint:v3:");
    aad.extend_from_slice(thread_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(checkpoint_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(&step_index.to_be_bytes());
    aad.push(b':');
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad
}

pub fn build_archive_aad(thread_id: &str, checkpoint_id: &str, key_epoch: u32) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"tantry:archive:v3:");
    aad.extend_from_slice(thread_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(checkpoint_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad
}

pub fn build_semcache_aad(cache_key_hex: &str, model_tier: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"tantry:semcache:v3:");
    aad.extend_from_slice(cache_key_hex.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(model_tier.as_bytes());
    aad
}
"""

# Insert right after compute_canonical_aad
anchor = """    hasher.update(&key_epoch.to_be_bytes());
    hasher.finalize().into()
}"""

if anchor not in content:
    print("Error: Could not find anchor")
    sys.exit(1)

new_content = content.replace(anchor, anchor + new_functions)
open('crates/data/src/crypto.rs', 'w').write(new_content)
print("Updated crypto.rs")
