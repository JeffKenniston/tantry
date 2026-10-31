use serde::{Deserialize, Serialize};

use crate::ast::{CacheControl, ToolCallId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelTier {
    FrontierDeep,
    ReasoningPro,
    FastExecution,
    CompactLite,
}

impl ModelTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FrontierDeep => "FrontierDeep",
            Self::ReasoningPro => "ReasoningPro",
            Self::FastExecution => "FastExecution",
            Self::CompactLite => "CompactLite",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "FrontierDeep" => Some(Self::FrontierDeep),
            "ReasoningPro" => Some(Self::ReasoningPro),
            "FastExecution" => Some(Self::FastExecution),
            "CompactLite" => Some(Self::CompactLite),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub cached_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approve { tool_use_id: ToolCallId },
    Edit { tool_use_id: ToolCallId, modified_arguments: serde_json::Value },
    Reject { tool_use_id: ToolCallId, feedback: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoopDirective {
    ContinueTurn,
    FinishTurn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamEvent {
    ModelDelta { text_delta: String, reasoning_delta: Option<String> },
    ToolCallStart { tool_use_id: ToolCallId, name: String },
    ToolCallEnd { tool_use_id: ToolCallId, is_error: bool },
    Interrupted { thread_id: String, checkpoint_id: String, pending_tools: Vec<ToolCallId> },
    TurnComplete { step_index: u64, usage: TokenUsage },
}

impl StreamEvent {
    pub fn coalesce_in_place(&mut self, next: StreamEvent) -> Result<(), StreamEvent> {
        match (self, next) {
            (
                StreamEvent::ModelDelta { text_delta: text_a, reasoning_delta: r_a },
                StreamEvent::ModelDelta { text_delta: text_b, reasoning_delta: r_b },
            ) => {
                text_a.push_str(&text_b);
                if let Some(rb) = r_b {
                    if let Some(ra) = r_a {
                        ra.push_str(&rb);
                    } else {
                        *r_a = Some(rb);
                    }
                }
                Ok(())
            }
            (_, next) => Err(next), // Refuses to coalesce other events
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PromptBlock {
    Block1StaticSystem(String),
    Block2StaticTools { tools_json: String, cache_control: CacheControl },
    Block3SemiStaticSkillsAndRepoMap { skills_catalog: String, repo_map: String },
    Block4SemiStaticMemory { memory_text: String, cache_control: CacheControl },
    Block5DynamicTurnState { todos_text: String, async_tasks_text: String },
}
