use base::ast::{ContentBlock, ToolCallId, Message, Role};
use base::delta::MessageDelta;
use base::execution::ApprovalDecision;
use crate::slots::{HitlBypassSlot, TurnDeltaBufferSlot};
use base::state::TantryState;

#[derive(Debug)]
pub enum RuntimeError {
    StateRehydrationFailed(String),
}

/// Resume interrupted thread and apply HITL decisions
pub fn resume_interrupted_thread(
    state: &mut TantryState,
    decisions: Vec<ApprovalDecision>,
    turn_buffer: &mut TurnDeltaBufferSlot,
    bypass_slot: &mut HitlBypassSlot,
) -> Result<(), RuntimeError> {

    for decision in decisions {
        match decision {
            ApprovalDecision::Approve { tool_use_id } => {
                bypass_slot.approved_tool_use_ids.insert(tool_use_id);
            },
            ApprovalDecision::Edit { tool_use_id, modified_arguments } => {
                let delta = build_tool_use_edit_delta(state, &tool_use_id, modified_arguments)?;
                if let Some(d) = delta {
                    turn_buffer.message_deltas.push(d);
                }
                bypass_slot.approved_tool_use_ids.insert(tool_use_id);
            },
            ApprovalDecision::Reject { tool_use_id, feedback } => {
                let content = ContentBlock::ToolResult {
                    tool_use_id,
                    is_error: true,
                    content: vec![ContentBlock::Text { text: feedback, cache_control: None }],
                    artifact: None,
                };

                let msg = Message {
                    id: base::ast::MessageId::default(),
                    role: Role::Tool,
                    content: vec![content],
                    created_at: chrono::Utc::now(),
                    metadata: std::collections::BTreeMap::new(),
                };

                state.messages.push(msg);
            }
        }
    }

    Ok(())
}

fn build_tool_use_edit_delta(
    state: &TantryState,
    tool_use_id: &ToolCallId,
    modified_arguments: serde_json::Value
) -> Result<Option<MessageDelta>, RuntimeError> {
    for msg in &state.messages {
        for (i, block) in msg.content.iter().enumerate() {
            if let ContentBlock::ToolUse { id, name, .. } = block {
                if id == tool_use_id {
                    let mut new_msg = msg.clone();
                    new_msg.content[i] = ContentBlock::ToolUse {
                        id: id.clone(),
                        name: name.clone(),
                        input: modified_arguments,
                    };
                    return Ok(Some(MessageDelta::PatchById {
                        target_id: msg.id,
                        replacement: new_msg,
                    }));
                }
            }
        }
    }
    Ok(None)
}
