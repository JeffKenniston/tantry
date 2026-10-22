use crate::ast::{AsyncTaskHandle, ContentBlock, Message, SkillFrontmatter, TaskId, TodoItem};
use crate::delta::MessageDelta;
use crate::error::StateReducerError;
use crate::path::PosixPath;
use crate::typemap::StateExtensionMap;
use crate::vfs::VfsTree;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RubricOutcome {
    Pass,
    Fail { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubagentMode {
    Isolated,
    Fork,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TantryState {
    pub thread_id: String,
    pub step_index: u64,
    pub last_checkpoint_id: Option<String>,
    pub messages: Vec<Message>,
    pub files: VfsTree,
    pub todos: Vec<TodoItem>,
    pub skills_metadata: Vec<SkillFrontmatter>,
    pub memory_contents: BTreeMap<PosixPath, String>,
    pub async_tasks: BTreeMap<TaskId, AsyncTaskHandle>,
    pub rubric_input: Option<String>,
    pub rubric_status: Option<RubricOutcome>,
    pub structured_response: Option<serde_json::Value>,
    pub extensions: StateExtensionMap,
}

impl TantryState {
    pub fn fork_for_subagent(
        &self,
        mode: SubagentMode,
        child_thread_id: String,
        task_prompt: Message,
    ) -> Self {
        let messages = match mode {
            SubagentMode::Isolated => vec![task_prompt],
            SubagentMode::Fork => {
                let mut msgs = self.messages.clone();
                msgs.push(task_prompt);
                msgs
            }
        };

        Self {
            thread_id: child_thread_id,
            step_index: 0,
            last_checkpoint_id: None,
            messages,
            files: self.files.clone(), // $O(1)$ Arc clone
            todos: Vec::new(),
            skills_metadata: Vec::new(),
            memory_contents: BTreeMap::new(),
            async_tasks: BTreeMap::new(),
            rubric_input: None,
            rubric_status: None,
            structured_response: None,
            extensions: self.extensions.fork_shared_only(),
        }
    }

    pub fn build_tool_use_edit_delta(
        &self,
        tool_use_id: &str,
        modified_arguments: serde_json::Value,
    ) -> Result<MessageDelta, StateReducerError> {
        let mut target_msg: Option<&Message> = None;
        let mut patch_idx = None;

        for msg in self.messages.iter().rev() {
            if let Some(idx) = msg.content.iter().position(|block| {
                if let ContentBlock::ToolUse { id, .. } = block {
                    id == tool_use_id
                } else {
                    false
                }
            }) {
                target_msg = Some(msg);
                patch_idx = Some(idx);
                break;
            }
        }

        if let (Some(msg), Some(idx)) = (target_msg, patch_idx) {
            let mut replacement = msg.clone();
            if let ContentBlock::ToolUse { ref mut input, .. } = replacement.content[idx] {
                *input = modified_arguments;
            }
            Ok(MessageDelta::PatchById {
                target_id: msg.id,
                replacement,
            })
        } else {
            Err(StateReducerError::InvalidToolUsePatch(
                tool_use_id.to_string(),
            ))
        }
    }
}
