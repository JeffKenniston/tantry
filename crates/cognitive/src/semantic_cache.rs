use base::ast::{ContentBlock, Message};
use base::execution::ModelTier;
use blake3::Hasher;
use data::vector_index::MatryoshkaVectorStore;
use std::sync::Arc;

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// Semantic Cache for LLM responses with bit-identical SIMD Int8 dot-product acceleration.
pub struct SemanticCache {
    /// Vector store containing cached embeddings and payloads.
    pub store: Arc<MatryoshkaVectorStore>,
}

impl SemanticCache {
    /// Creates a new SemanticCache wrapper.
    pub fn new(store: Arc<MatryoshkaVectorStore>) -> Self {
        Self { store }
    }

    /// Computes the context partition key for the cache index.
    pub fn compute_partition_key(
        tier: ModelTier,
        sorted_tool_names_blake3: &[u8; 32],
        block1_system_blake3: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(tier.as_str().as_bytes());
        hasher.update(sorted_tool_names_blake3);
        hasher.update(block1_system_blake3);
        hasher.finalize().into()
    }

    /// Mutation Bypass Invariant: skips cache lookup if a mutating tool was just used.
    pub fn check_mutation_bypass(messages: &[Message]) -> bool {
        let mut mutating_tools = std::collections::HashSet::new();

        for msg in messages.iter() {
            for block in &msg.content {
                if let ContentBlock::ToolUse { id, name, .. } = block {
                    if matches!(
                        name.as_str(),
                        "write_file"
                            | "edit_file"
                            | "delete"
                            | "execute"
                            | "eval"
                            | "browser"
                            | "computer"
                            | "task"
                    ) {
                        mutating_tools.insert(id.clone());
                    }
                }
            }
        }

        if let Some(msg) = messages.last() {
            for block in &msg.content {
                if let ContentBlock::ToolResult { tool_use_id, .. } = block {
                    if mutating_tools.contains(tool_use_id) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Computes the dot product of two i8 arrays. Uses AVX2 or NEON when available.
    pub fn dot_product_i8(a: &[i8], b: &[i8]) -> i32 {
        assert_eq!(a.len(), b.len(), "Vectors must be of equal length");

        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                return unsafe { Self::dot_product_i8_neon(a, b) };
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                return unsafe { Self::dot_product_i8_avx2(a, b) };
            }
        }

        Self::dot_product_i8_scalar(a, b)
    }

    fn dot_product_i8_scalar(a: &[i8], b: &[i8]) -> i32 {
        a.iter()
            .zip(b.iter())
            .map(|(&x, &y)| (x as i32) * (y as i32))
            .sum()
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn dot_product_i8_neon(a: &[i8], b: &[i8]) -> i32 {
        let mut sum = 0;
        let chunks = a.len() / 16;
        let mut acc = vdupq_n_s32(0);

        for i in 0..chunks {
            let va = vld1q_s8(a.as_ptr().add(i * 16));
            let vb = vld1q_s8(b.as_ptr().add(i * 16));
            acc = vdotq_s32(acc, va, vb);
        }

        let mut temp = [0; 4];
        vst1q_s32(temp.as_mut_ptr(), acc);
        sum = temp.iter().sum();

        for i in chunks * 16..a.len() {
            sum += (a[i] as i32) * (b[i] as i32);
        }
        sum
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    #[allow(unsafe_op_in_unsafe_fn)]
    unsafe fn dot_product_i8_avx2(a: &[i8], b: &[i8]) -> i32 {
        let mut sum = 0;
        let chunks = a.len() / 16;
        let mut acc = _mm256_setzero_si256();

        for i in 0..chunks {
            let va = _mm_loadu_si128(a.as_ptr().add(i * 16) as *const __m128i);
            let vb = _mm_loadu_si128(b.as_ptr().add(i * 16) as *const __m128i);

            let va16 = _mm256_cvtepi8_epi16(va);
            let vb16 = _mm256_cvtepi8_epi16(vb);

            let prod = _mm256_madd_epi16(va16, vb16);
            acc = _mm256_add_epi32(acc, prod);
        }

        let mut temp = [0; 8];
        _mm256_storeu_si256(temp.as_mut_ptr() as *mut __m256i, acc);
        sum += temp.iter().sum::<i32>();

        for i in chunks * 16..a.len() {
            sum += (a[i] as i32) * (b[i] as i32);
        }
        sum
    }

    pub fn store_payload(&self, key_id: &str, messages: &[Message], dek: &[u8; 32], aad: &[u8; 32]) -> Result<(), crate::error::CognitiveError> {
        let plaintext = serde_json::to_vec(messages)
            .map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))?;

        let encrypted = data::crypto::encrypt_envelope_xchacha20(&plaintext, dek, aad)
            .map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))?;

        let conn = self.store.db.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS semantic_cache_payloads (
                id TEXT PRIMARY KEY,
                payload BLOB
            )", []
        ).map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))?;

        conn.execute(
            "INSERT INTO semantic_cache_payloads (id, payload) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
            rusqlite::params![key_id, encrypted]
        ).map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))?;

        Ok(())
    }


    pub fn lookup(&self, messages: &[Message], query_embedding: &[f32], dek: &[u8; 32], expected_aad: &[u8; 32]) -> Result<Option<Vec<Message>>, crate::error::CognitiveError> {
        if Self::check_mutation_bypass(messages) {
            return Ok(None);
        }

        let candidates = self.store.search(query_embedding, 1, 0.8)
            .map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))?;

        if let Some((best_id, _score)) = candidates.first() {
            return self.retrieve_payload(best_id, dek, expected_aad);
        }

        Ok(None)
    }

    pub fn retrieve_payload(&self, key_id: &str, dek: &[u8; 32], expected_aad: &[u8; 32]) -> Result<Option<Vec<Message>>, crate::error::CognitiveError> {
        let conn = self.store.db.lock().unwrap();

        // Ensure the table exists before querying.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS semantic_cache_payloads (
                id TEXT PRIMARY KEY,
                payload BLOB
            )", []
        ).map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))?;

        let mut stmt = conn.prepare("SELECT payload FROM semantic_cache_payloads WHERE id = ?1")
            .map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))?;

        let mut rows = stmt.query([key_id])
            .map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))? {
            let encrypted: Vec<u8> = row.get(0).map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))?;
            let plaintext = data::crypto::decrypt_envelope(&encrypted, dek, expected_aad)
                .map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))?;

            let messages = serde_json::from_slice(&plaintext)
                .map_err(|e| crate::error::CognitiveError::DatabaseError(e.to_string()))?;

            Ok(Some(messages))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dot_product() {
        let a: Vec<i8> = (0..32).map(|x| (x % 10) as i8).collect();
        let b: Vec<i8> = (0..32).map(|x| (x % 5) as i8).collect();
        let s = SemanticCache::dot_product_i8(&a, &b);
        let expected_s: i32 = a.iter().zip(b.iter()).map(|(&x, &y)| (x as i32) * (y as i32)).sum();
        assert_eq!(s, expected_s);
    }
}
