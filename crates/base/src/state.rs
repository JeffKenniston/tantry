use std::collections::BTreeMap;
use serde_json::Value;

use crate::ast::{
    AsyncTaskHandle, Message, ContentBlock, RubricOutcome, SkillFrontmatter, SubagentMode, TaskId,
    TodoItem,
};
use crate::delta::MessageDelta;
use crate::error::StateReducerError;
use crate::path::PosixPath;
use crate::typemap::StateExtensionMap;
use crate::vfs_tree::VfsTree;

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
    pub structured_response: Option<Value>,
    pub extensions: StateExtensionMap,
}

impl Default for TantryState {
    fn default() -> Self {
        Self {
            thread_id: "".to_string(),
            step_index: 0,
            last_checkpoint_id: None,
            messages: vec![],
            files: VfsTree::new(),
            todos: vec![],
            skills_metadata: vec![],
            memory_contents: BTreeMap::new(),
            async_tasks: BTreeMap::new(),
            rubric_input: None,
            rubric_status: None,
            structured_response: None,
            extensions: StateExtensionMap::new(),
        }
    }
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
            files: self.files.clone(),
            todos: vec![],
            skills_metadata: vec![],
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
        modified_arguments: Value,
    ) -> Result<MessageDelta, StateReducerError> {
        for msg in self.messages.iter().rev() {
            let mut found = false;
            let mut new_content = msg.content.clone();

            for block in &mut new_content {
                if let ContentBlock::ToolUse { id, input, .. } = block {
                    if id == tool_use_id {
                        *input = modified_arguments.clone();
                        found = true;
                        break;
                    }
                }
            }

            if found {
                let mut replacement = msg.clone();
                replacement.content = new_content;
                return Ok(MessageDelta::PatchById {
                    target_id: msg.id,
                    replacement,
                });
            }
        }

        // According to strict specs we might want to return a different error if message not found vs tool use not found,
        // but StateReducerError doesn't have a specific variant for tool use not found besides InvalidToolUsePatch
        Err(StateReducerError::InvalidToolUsePatch(format!("ToolUse {} not found", tool_use_id)))
    }
}
