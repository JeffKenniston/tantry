use std::collections::BTreeMap;
use crate::ast::{Message, TodoItem, SkillFrontmatter, AsyncTaskHandle, RubricOutcome, SubagentMode, ContentBlock};
use crate::vfs_tree::VfsTree;
use crate::typemap::StateExtensionMap;
use crate::path::PosixPath;
use crate::ast::TaskId;
use crate::delta::MessageDelta;
use crate::error::StateReducerError;

#[derive(Default)]
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
    pub fn fork_for_subagent(&self, mode: SubagentMode, child_thread_id: String, task_prompt: Message) -> Self {
        let mut child = Self {
            thread_id: child_thread_id,
            step_index: 0,
            last_checkpoint_id: None,
            messages: Vec::new(),
            files: self.files.clone(),
            todos: Vec::new(),
            skills_metadata: Vec::new(),
            memory_contents: BTreeMap::new(),
            async_tasks: BTreeMap::new(),
            rubric_input: None,
            rubric_status: None,
            structured_response: None,
            extensions: self.extensions.fork_shared_only(),
        };

        match mode {
            SubagentMode::Isolated => {
                child.messages = vec![task_prompt];
            }
            SubagentMode::Fork => {
                child.messages = self.messages.clone();
                child.messages.push(task_prompt);
            }
        }

        child
    }

    pub fn build_tool_use_edit_delta(&self, tool_use_id: &str, modified_arguments: serde_json::Value) -> Result<MessageDelta, StateReducerError> {
        for msg in self.messages.iter().rev() {
            let mut found = false;
            let mut cloned_msg = msg.clone();

            for block in &mut cloned_msg.content {
                if let ContentBlock::ToolUse { tool_call_id, input, .. } = block {
                    if tool_call_id == tool_use_id {
                        found = true;
                        *input = modified_arguments.clone();
                    }
                }
            }

            if found {
                return Ok(MessageDelta::PatchById(cloned_msg.id.clone(), cloned_msg));
            }
        }

        Err(StateReducerError::InvalidToolUsePatch(tool_use_id.to_string()))
    }
}
