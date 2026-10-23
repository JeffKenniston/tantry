use std::collections::BTreeMap;

use crate::ast::{
    AsyncTaskHandle, ContentBlock, Message, RubricOutcome, SkillFrontmatter,
    SubagentMode, TaskId, TodoItem,
};
use crate::path::PosixPath;
use crate::delta::MessageDelta;
use crate::error::StateReducerError;
use crate::typemap::StateExtensionMap;
use crate::vfs_tree::VfsTree;

#[derive(Debug, Clone, PartialEq)]
/// TantryState struct
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
    /// fork_for_subagent fn
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
            files: self.files.clone(),
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

    /// build_tool_use_edit_delta fn
    pub fn build_tool_use_edit_delta(
        &self,
        tool_use_id: &str,
        modified_arguments: serde_json::Value,
    ) -> Result<MessageDelta, StateReducerError> {
        for msg in self.messages.iter().rev() {
            let has_target_tool = msg.content.iter().any(|block| {
                if let ContentBlock::ToolUse { id, .. } = block {
                    id == tool_use_id
                } else {
                    false
                }
            });

            if has_target_tool {
                let mut replacement = msg.clone();
                for block in &mut replacement.content {
                    if let ContentBlock::ToolUse { id, input, .. } = block {
                        #[allow(clippy::collapsible_if)]
                        if id == tool_use_id {
                            *input = modified_arguments.clone();
                        }
                    }
                }
                return Ok(MessageDelta::PatchById {
                    target_id: msg.id,
                    replacement,
                });
            }
        }

        Err(StateReducerError::InvalidToolUsePatch(tool_use_id.to_string()))
    }
}
