use base::error::ExtensionError;
use base::typemap::{CodecTag, SlotVisibility, StateSlot};
use rkyv::{Archive, Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    Archive,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct SubagentDepthSlot {
    pub depth: u8,
}

impl StateSlot for SubagentDepthSlot {
    const WIRE_KEY: &'static str = "tantry.middleware.subagent_depth";
    const VISIBILITY: SlotVisibility = SlotVisibility::Shared;
    const CODEC_TAG: CodecTag = CodecTag::RkyvAligned;

    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError> {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map_err(|e| ExtensionError::SerializationFailed(e.to_string()))?;
        Ok(bytes.into_vec())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError> {
        let archived = rkyv::access::<rkyv::Archived<Self>, rkyv::rancor::Error>(bytes)
            .map_err(|e| ExtensionError::DeserializationFailed(e.to_string()))?;
        let deserialized: Self = rkyv::deserialize::<Self, rkyv::rancor::Error>(archived)
            .map_err(|e| ExtensionError::DeserializationFailed(e.to_string()))?;
        Ok(deserialized)
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    Archive,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct RubricIterationSlot {
    pub iterations: u32,
}

impl StateSlot for RubricIterationSlot {
    const WIRE_KEY: &'static str = "tantry.middleware.rubric_iteration";
    const VISIBILITY: SlotVisibility = SlotVisibility::Private;
    const CODEC_TAG: CodecTag = CodecTag::RkyvAligned;

    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError> {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map_err(|e| ExtensionError::SerializationFailed(e.to_string()))?;
        Ok(bytes.into_vec())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError> {
        let archived = rkyv::access::<rkyv::Archived<Self>, rkyv::rancor::Error>(bytes)
            .map_err(|e| ExtensionError::DeserializationFailed(e.to_string()))?;
        let deserialized: Self = rkyv::deserialize::<Self, rkyv::rancor::Error>(archived)
            .map_err(|e| ExtensionError::DeserializationFailed(e.to_string()))?;
        Ok(deserialized)
    }
}
