use backends::error::BackendError;
use base::error::BaseError;
use data::error::DataError;
use iam::error::IamError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("base error: {0}")]
    Base(#[from] BaseError),
    #[error("iam error: {0}")]
    Iam(#[from] IamError),
    #[error("data error: {0}")]
    Data(#[from] DataError),
    #[error("backend error: {0}")]
    Backend(#[from] BackendError),
    #[error("cognitive error: {0}")]
    Cognitive(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("checkpoint not found: {0}")]
    CheckpointNotFound(String),
    #[error("checkpoint integrity mismatch: {checkpoint_id}")]
    CheckpointIntegrityMismatch { checkpoint_id: String },
    #[error("tool execution denied: {tool_name}")]
    ToolExecutionDenied { tool_name: String },
    #[error("subagent recursion limit exceeded: {0}")]
    SubagentRecursionLimitExceeded(u8),
    #[error("middleware error in {slot_name}: {reason}")]
    MiddlewareError { slot_name: String, reason: String },
}

impl From<cognitive::error::CognitiveError> for RuntimeError {
    fn from(err: cognitive::error::CognitiveError) -> Self {
        RuntimeError::Cognitive(err.to_string())
    }
}

impl From<transport::TransportError> for RuntimeError {
    fn from(err: transport::TransportError) -> Self {
        RuntimeError::Transport(err.to_string())
    }
}
