use crate::ast::{CacheControl, ToolCallId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
/// ModelTier enum
pub enum ModelTier {
    FrontierDeep,
    ReasoningPro,
    FastExecution,
    CompactLite,
}

impl ModelTier {
    /// as_str fn
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FrontierDeep => "FrontierDeep",
            Self::ReasoningPro => "ReasoningPro",
            Self::FastExecution => "FastExecution",
            Self::CompactLite => "CompactLite",
        }
    }

    #[allow(clippy::should_implement_trait)]
    /// from_str fn
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
/// TokenUsage struct
pub struct TokenUsage {
    pub input_tokens: u64,
    pub cached_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// ToolDefinition struct
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// ApprovalDecision enum
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
/// LoopDirective enum
pub enum LoopDirective {
    ContinueTurn,
    FinishTurn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// StreamEvent enum
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
    /// coalesce_in_place fn
    pub fn coalesce_in_place(&mut self, next: StreamEvent) -> Result<(), StreamEvent> {
        if let StreamEvent::ModelDelta {
            text_delta,
            reasoning_delta,
        } = self
        {
            if let StreamEvent::ModelDelta {
                text_delta: next_text,
                reasoning_delta: next_reasoning,
            } = next
            {
                text_delta.push_str(&next_text);
                if let Some(nr) = next_reasoning {
                    if let Some(r) = reasoning_delta {
                        r.push_str(&nr);
                    } else {
                        *reasoning_delta = Some(nr);
                    }
                }
                Ok(())
            } else {
                Err(next)
            }
        } else {
            Err(next)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// PromptBlock enum
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
