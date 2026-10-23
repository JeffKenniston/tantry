use base::error::ExtensionError;
use base::typemap::{CodecTag, SlotVisibility, StateSlot};

/// A token-budgeted skeletonized `RepoMap` slot.
#[derive(Debug, Clone, PartialEq)]
pub struct SkeletonRepoMapSlot {
    /// The maximum number of tokens allowed.
    pub max_tokens: u64,
    /// The serialized payload.
    pub payload: Vec<u8>,
}

impl SkeletonRepoMapSlot {
    /// Creates a new `SkeletonRepoMapSlot` with a specific token limit.
    pub fn new(max_tokens: u64) -> Self {
        Self {
            max_tokens,
            payload: Vec::new(),
        }
    }
}

impl Default for SkeletonRepoMapSlot {
    fn default() -> Self {
        Self::new(2500)
    }
}

impl StateSlot for SkeletonRepoMapSlot {
    const WIRE_KEY: &'static str = "tantry.repo.skeleton_map";
    const VISIBILITY: SlotVisibility = SlotVisibility::Shared;
    const CODEC_TAG: CodecTag = CodecTag::MessagePackNamed;

    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError> {
        let mut encoded = self.max_tokens.to_be_bytes().to_vec();
        encoded.extend(&self.payload);
        Ok(encoded)
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError> {
        if bytes.len() >= 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[..8]);
            let max_tokens = u64::from_be_bytes(arr);
            let payload = bytes[8..].to_vec();
            Ok(Self { max_tokens, payload })
        } else {
            Err(ExtensionError::DeserializationFailed("Invalid SkeletonRepoMapSlot payload".to_string()))
        }
    }
}

impl SkeletonRepoMapSlot {
    /// Ranks workspace files and symbols, elides function bodies, and packs declarations.
    pub fn build_skeleton_repomap(
        &mut self,
        _files: &[&str],
        symbols: &[&str],
        centrality: &std::collections::HashMap<String, f32>,
        user_prompt_hits: &[&str],
    ) {
        let mut ranked_symbols: Vec<(&str, f32)> = symbols
            .iter()
            .map(|&sym| {
                let mut score = *centrality.get(sym).unwrap_or(&1.0);
                if user_prompt_hits.iter().any(|&hit| sym.contains(hit)) {
                    score *= 3.0;
                }
                (sym, score)
            })
            .collect();

        ranked_symbols.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut result = String::new();
        let mut current_tokens = 0;

        for (sym, _) in ranked_symbols {
            let decl = format!("{} {{ ... }}\n", sym);
            let tokens = (decl.len() as f64 / 4.0).ceil() as u64;
            if current_tokens + tokens > self.max_tokens {
                break;
            }
            result.push_str(&decl);
            current_tokens += tokens;
        }

        self.payload = result.into_bytes();
    }
}
