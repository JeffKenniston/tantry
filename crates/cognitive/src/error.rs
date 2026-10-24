use thiserror::Error;

#[derive(Debug, Error)]
pub enum CognitiveError {
    #[error("Budget exhausted: {0}")]
    BudgetExhausted(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("MCP sampling recursion limit exceeded: {0}")]
    McpSamplingRecursionLimitExceeded(u32),
}
