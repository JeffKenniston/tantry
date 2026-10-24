use blake3::Hasher;

/// Computes deterministic chained BLAKE3 prefix hashes for provider KV-cache accounting.
pub struct PrefixHasher;

impl PrefixHasher {
    /// Computes Hash_BP1 by hashing the 'tantry:kv:bp1:v3' prefix, block 1 static system prompt, and block 2 static tools.
    pub fn compute_bp1(block1_system: &str, tools_json: &str) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"tantry:kv:bp1:v3");
        hasher.update(block1_system.as_bytes());
        hasher.update(tools_json.as_bytes());
        hasher.finalize().into()
    }

    /// Computes Hash_BP2 by hashing the 'tantry:kv:bp2:v3' prefix, Hash_BP1, block 3 semi-static skills and repo map, and block 4 semi-static memory.
    pub fn compute_bp2(
        hash_bp1: &[u8; 32],
        skills_catalog: &str,
        repo_map: &str,
        memory_text: &str,
    ) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"tantry:kv:bp2:v3");
        hasher.update(hash_bp1);
        hasher.update(skills_catalog.as_bytes());
        hasher.update(repo_map.as_bytes());
        hasher.update(memory_text.as_bytes());
        hasher.finalize().into()
    }
}

/// Calculates the KV-cache hit ratio as `cached_tokens / max(input_tokens, 1)`.
pub fn tantry_kv_cache_hit_ratio(cached_tokens: u64, input_tokens: u64) -> f64 {
    (cached_tokens as f64) / (input_tokens.max(1) as f64)
}
