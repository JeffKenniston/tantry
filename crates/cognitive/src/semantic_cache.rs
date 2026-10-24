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
        // ToolResult in AST does not contain tool name.
        // The check will be more complex if we need tool name.
        // Wait, wait... Let me look at specs...
        // The specs say: "if the latest message in state.messages contains a ContentBlock::ToolResult from any tool where is_mutating_for_semantic_cache == true (write_file, edit_file, delete, execute, eval, browser, computer, task)"
        // Since ToolResult does not hold name, how do we know? We'd have to look back at the ToolUse block.
        // I'll implement exactly that.
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
}
