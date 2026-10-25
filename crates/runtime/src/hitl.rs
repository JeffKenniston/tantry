use base::ast::{ToolCallId, Message};
use base::delta::MessageDelta;
use crate::error::RuntimeError;
use crate::slots::{HitlBypassSlot, TurnDeltaBufferSlot};
use crate::time_travel::TimeTravelEngine;
use uuid::Uuid;
use std::str::FromStr;

pub enum ApprovalDecision {
    Approve { tool_use_id: ToolCallId },
    Edit { tool_use_id: ToolCallId, modified_arguments: serde_json::Value },
    Reject { tool_use_id: ToolCallId, feedback: String },
}

pub struct HitlManager;

impl HitlManager {
    pub fn resume_interrupted_thread(
        thread_id: &str,
        time_travel: &TimeTravelEngine,
        decisions: Vec<ApprovalDecision>,
    ) -> Result<(), RuntimeError> {
        let mut hydrated = time_travel.hydrate_thread_state(thread_id)?;

        let has_hitl = hydrated.state.extensions.get::<HitlBypassSlot>().is_some();
        if !has_hitl {
            hydrated.state.extensions.insert(HitlBypassSlot {
                approved_tool_use_ids: std::collections::BTreeSet::new(),
            });
        }

        let has_delta = hydrated.state.extensions.get::<TurnDeltaBufferSlot>().is_some();
        if !has_delta {
            hydrated.state.extensions.insert(TurnDeltaBufferSlot {
                message_deltas: Vec::new(),
            });
        }

        let mut hitl_slot = hydrated.state.extensions.get::<HitlBypassSlot>().unwrap().clone();
        let mut delta_slot = hydrated.state.extensions.get::<TurnDeltaBufferSlot>().unwrap().clone();

        for decision in decisions {
            match decision {
                ApprovalDecision::Approve { tool_use_id } => {
                    hitl_slot.approved_tool_use_ids.insert(tool_use_id);
                }
                ApprovalDecision::Edit { tool_use_id, modified_arguments } => {
                    let tid = Uuid::from_str(&tool_use_id).unwrap_or_else(|_| Uuid::nil());
                    let mut found_name = "".to_string();
                    for msg in &hydrated.state.messages {
                        for block in &msg.content {
                            if let base::ast::ContentBlock::ToolUse { id, name, .. } = block {
                                if id == &tool_use_id {
                                    found_name = name.clone();
                                }
                            }
                        }
                    }

                    let delta = MessageDelta::PatchById {
                        target_id: tid,
                        replacement: Message::assistant(vec![base::ast::ContentBlock::ToolUse {
                            id: tool_use_id.clone(),
                            name: found_name,
                            input: modified_arguments,
                        }]),
                    };
                    MessageDelta::apply(&mut hydrated.state.messages, delta.clone())?;
                    delta_slot.message_deltas.push(delta);
                    hitl_slot.approved_tool_use_ids.insert(tool_use_id);
                }
                ApprovalDecision::Reject { tool_use_id, feedback } => {
                    let msg = Message::tool_result(tool_use_id, true, feedback, None);
                    hydrated.state.messages.push(msg.clone());
                    delta_slot.message_deltas.push(MessageDelta::Append(vec![msg]));
                }
            }
        }

        hydrated.state.extensions.insert(hitl_slot);
        hydrated.state.extensions.insert(delta_slot);

        Ok(())
    }
}
