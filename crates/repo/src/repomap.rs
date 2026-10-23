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
