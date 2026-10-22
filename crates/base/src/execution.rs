use crate::ast::{CacheControl, ToolCallId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelTier {
    FrontierDeep,
    ReasoningPro,
    FastExecution,
    CompactLite,
}

impl ModelTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModelTier::FrontierDeep => "frontier_deep",
            ModelTier::ReasoningPro => "reasoning_pro",
            ModelTier::FastExecution => "fast_execution",
            ModelTier::CompactLite => "compact_lite",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "frontier_deep" => Some(ModelTier::FrontierDeep),
            "reasoning_pro" => Some(ModelTier::ReasoningPro),
            "fast_execution" => Some(ModelTier::FastExecution),
            "compact_lite" => Some(ModelTier::CompactLite),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub cached_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approve {
        tool_use_id: ToolCallId,
    },
    Edit {
        tool_use_id: ToolCallId,
        modified_arguments: serde_json::Value,
    },
    Reject {
        tool_use_id: ToolCallId,
        feedback: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoopDirective {
    ContinueTurn,
    FinishTurn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StreamEvent {
    ModelDelta {
        text_delta: String,
        reasoning_delta: Option<String>,
    },
    ToolCallStart {
        tool_use_id: ToolCallId,
        name: String,
    },
    ToolCallEnd {
        tool_use_id: ToolCallId,
        is_error: bool,
    },
    Interrupted {
        thread_id: String,
        checkpoint_id: String,
        pending_tools: Vec<ToolCallId>,
    },
    TurnComplete {
        step_index: u64,
        usage: TokenUsage,
    },
}

impl StreamEvent {
    pub fn coalesce_in_place(&mut self, next: StreamEvent) -> Result<(), StreamEvent> {
        if let StreamEvent::ModelDelta {
            text_delta: cur_text,
            reasoning_delta: cur_reasoning,
        } = self
        {
            if let StreamEvent::ModelDelta {
                text_delta: next_text,
                reasoning_delta: next_reasoning,
            } = next
            {
                cur_text.push_str(&next_text);

                if let Some(next_r) = next_reasoning {
                    if let Some(cur_r) = cur_reasoning {
                        cur_r.push_str(&next_r);
                    } else {
                        *cur_reasoning = Some(next_r);
                    }
                }

                return Ok(());
            } else {
                return Err(next);
            }
        }

        Err(next)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PromptBlock {
    Block1StaticSystem(String),
    Block2StaticTools {
        tools_json: String,
        cache_control: CacheControl,
    },
    Block3SemiStaticSkillsAndRepoMap {
        skills_catalog: String,
        repo_map: String,
    },
    Block4SemiStaticMemory {
        memory_text: String,
        cache_control: CacheControl,
    },
    Block5DynamicTurnState {
        todos_text: String,
        async_tasks_text: String,
    },
}
