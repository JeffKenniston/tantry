use base::error::{BaseError, ExtensionError, PathValidationError, StateReducerError};
use iam::error::IamError;
use data::error::DataError;
use backends::error::BackendError;

/// Error taxonomy for runtime operations.
#[derive(thiserror::Error, Debug)]
pub enum RuntimeError {
    /// Base errors.
    #[error(transparent)]
    Base(#[from] BaseError),
    /// Path validation errors.
    #[error(transparent)]
    PathValidation(#[from] PathValidationError),
    /// State reducer errors.
    #[error(transparent)]
    StateReducer(#[from] StateReducerError),
    /// Extension errors.
    #[error(transparent)]
    Extension(#[from] ExtensionError),
    /// IAM errors.
    #[error(transparent)]
    Iam(#[from] IamError),
    /// Data errors.
    #[error(transparent)]
    Data(#[from] DataError),
    /// Backend errors.
    #[error(transparent)]
    Backend(#[from] BackendError),
    /// Cognitive errors.
    #[error("Cognitive error: {0}")]
    Cognitive(String),
    /// Transport errors.
    #[error("Transport error: {0}")]
    Transport(String),
    /// Checkpoint not found error.
    #[error("Checkpoint not found for thread: {0}")]
    CheckpointNotFound(String),
    /// State hash mismatch.
    #[error("State hash mismatch. Expected: {expected:?}, Actual: {actual:?}")]
    StateHashMismatch {
        /// Expected state hash.
        expected: [u8; 32],
        /// Actual state hash.
        actual: [u8; 32],
    },
    /// Subagent recursion limit exceeded.
    #[error("Subagent recursion limit exceeded: {0}")]
    SubagentRecursionLimitExceeded(u8),
    /// Tool execution failed.
    #[error("Tool '{tool_name}' execution failed: {reason}")]
    ToolExecutionFailed {
        /// Tool name.
        tool_name: String,
        /// Failure reason.
        reason: String,
    },
    /// Middleware error.
    #[error("Middleware error in slot '{slot_name}': {reason}")]
    MiddlewareError {
        /// Slot name.
        slot_name: String,
        /// Failure reason.
        reason: String,
    },
    /// Invalid HITL decision.
    #[error("Invalid HITL decision: {0}")]
    InvalidHitlDecision(String),
}
