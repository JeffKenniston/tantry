use std::collections::BTreeSet;
use base::ast::ToolCallId;
use base::delta::MessageDelta;
use base::typemap::{StateSlot, SlotVisibility, CodecTag};
use base::error::ExtensionError;
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HitlBypassSlot {
    pub approved_tool_use_ids: BTreeSet<ToolCallId>,
}

impl StateSlot for HitlBypassSlot {
    const WIRE_KEY: &'static str = "tantry.runtime.hitl_bypass";
    const VISIBILITY: SlotVisibility = SlotVisibility::Private;
    const CODEC_TAG: CodecTag = CodecTag::MessagePackNamed;

    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError> {
        rmp_serde::to_vec_named(self).map_err(|e| ExtensionError::SerializationFailed(e.to_string()))
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError> {
        rmp_serde::from_slice(bytes).map_err(|e| ExtensionError::DeserializationFailed(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TurnDeltaBufferSlot {
    pub message_deltas: Vec<MessageDelta>,
}

impl StateSlot for TurnDeltaBufferSlot {
    const WIRE_KEY: &'static str = "tantry.runtime.turn_delta_buffer";
    const VISIBILITY: SlotVisibility = SlotVisibility::Private;
    const CODEC_TAG: CodecTag = CodecTag::MessagePackNamed;

    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError> {
        rmp_serde::to_vec_named(self).map_err(|e| ExtensionError::SerializationFailed(e.to_string()))
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError> {
        rmp_serde::from_slice(bytes).map_err(|e| ExtensionError::DeserializationFailed(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct McpSamplingDepthSlot {
    pub depth: u8,
}

impl StateSlot for McpSamplingDepthSlot {
    const WIRE_KEY: &'static str = "tantry.runtime.mcp_sampling_depth";
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Archive, Serialize, Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct SubagentDepthSlot {
    pub depth: u8,
}

impl StateSlot for SubagentDepthSlot {
    const WIRE_KEY: &'static str = "tantry.runtime.subagent_depth";
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

pub fn register_runtime_slots(registry: &mut base::typemap::DefaultExtensionRegistryImpl) {
    base::typemap::register_slot::<HitlBypassSlot>(registry);
    base::typemap::register_slot::<TurnDeltaBufferSlot>(registry);
    base::typemap::register_slot::<McpSamplingDepthSlot>(registry);
    base::typemap::register_slot::<SubagentDepthSlot>(registry);
}
