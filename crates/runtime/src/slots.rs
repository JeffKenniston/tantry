use base::ast::ToolCallId;
use base::delta::MessageDelta;
use base::error::ExtensionError;
use base::typemap::{CodecTag, SlotVisibility, StateSlot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Slot for keeping track of HITL bypassed tool call IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitlBypassSlot {
    /// The set of approved tool call IDs.
    pub approved_tool_use_ids: BTreeSet<ToolCallId>,
}

impl StateSlot for HitlBypassSlot {
    const WIRE_KEY: &'static str = "tantry.runtime.hitl_bypass";
    const VISIBILITY: SlotVisibility = SlotVisibility::Private;
    const CODEC_TAG: CodecTag = CodecTag::MessagePackNamed;

    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| ExtensionError::SerializationFailed(e.to_string()))
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| ExtensionError::DeserializationFailed(e.to_string()))
    }
}

/// Slot for buffering message deltas within a turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TurnDeltaBufferSlot {
    /// The message deltas accumulated in the current turn.
    pub message_deltas: Vec<MessageDelta>,
}

impl StateSlot for TurnDeltaBufferSlot {
    const WIRE_KEY: &'static str = "tantry.runtime.turn_delta_buffer";
    const VISIBILITY: SlotVisibility = SlotVisibility::Private;
    const CODEC_TAG: CodecTag = CodecTag::MessagePackNamed;

    fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| ExtensionError::SerializationFailed(e.to_string()))
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| ExtensionError::DeserializationFailed(e.to_string()))
    }
}

/// Slot for sampling depth for MCP operations.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub struct McpSamplingDepthSlot {
    /// The sampling depth.
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
        let result: Self = rkyv::deserialize::<Self, rkyv::rancor::Error>(archived)
            .map_err(|e| ExtensionError::DeserializationFailed(e.to_string()))?;
        Ok(result)
    }
}
