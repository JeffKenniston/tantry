use std::str::FromStr;
use crate::error::ConfigValidationError;
use serde_json::Value;

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
            Self::FrontierDeep => "frontier-deep",
            Self::ReasoningPro => "reasoning-pro",
            Self::FastExecution => "fast-execution",
            Self::CompactLite => "compact-lite",
        }
    }
}

impl FromStr for ModelTier {
    type Err = ConfigValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "frontier-deep" => Ok(Self::FrontierDeep),
            "reasoning-pro" => Ok(Self::ReasoningPro),
            "fast-execution" => Ok(Self::FastExecution),
            "compact-lite" => Ok(Self::CompactLite),
            _ => Err(ConfigValidationError::InvalidModelTierFormat),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_creation_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value, // JSON schema for arguments
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved,
    Rejected(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopDirective {
    Continue,
    YieldToUser,
    EndTurn,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    ModelDelta { text: String, reasoning: String },
    ToolCallStart { id: String, name: String },
    ToolCallEnd { id: String },
    Interrupted,
    TurnComplete,
}

impl StreamEvent {
    pub fn coalesce_in_place(&mut self, next: StreamEvent) -> Result<(), StreamEvent> {
        if let (StreamEvent::ModelDelta { text: t1, reasoning: r1 }, StreamEvent::ModelDelta { text: t2, reasoning: r2 }) = (self, &next) {
            t1.push_str(t2);
            r1.push_str(r2);
            return Ok(());
        }
        Err(next)
    }
}

#[derive(Debug, Clone)]
pub enum PromptBlock {
    Block1StaticSystem,
    Block2StaticTools,
    Block3SemiStaticSkillsAndRepoMap,
    Block4SemiStaticMemory,
    Block5DynamicTurnState,
}
