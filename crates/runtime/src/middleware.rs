use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base::ast::{ToolArtifact, ToolCallId};
use base::execution::LoopDirective;
use base::execution::{ModelRequest, ModelResponse, ModelTier};
use base::state::TantryState;
use cognitive::cascade::LlmProvider;
use data::DataStoreManager;
use iam::IdentityManager;
use permissions::attenuation::PermissionLattice;
use permissions::lattice::PermissionMode;


use crate::error::RuntimeError;

pub type NextModelCall<'a> = Box<
    dyn FnOnce(
            &'a mut TantryState,
            ModelRequest,
        )
            -> Pin<Box<dyn Future<Output = Result<ModelResponse, RuntimeError>> + Send + 'a>>
        + Send
        + 'a,
>;

#[derive(Debug, Clone, Default)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ToolExecutionOutput {
    pub raw_output: String,
    pub is_error: bool,
    pub artifact: Option<ToolArtifact>,
}

pub struct TurnExecutionContext {
    pub task_id: String,
    pub tenant_id: String,
    pub iam: Arc<dyn IdentityManager>,
    pub permission_lattice: Arc<PermissionLattice>,
    pub data_stores: Arc<DataStoreManager>,
    pub llm_provider: Arc<dyn LlmProvider>,
    pub backend: Arc<dyn backends::traits::VfsBackend>,
    pub publisher: Option<Arc<transport::backpressure::CreditControlledPublisher>>,
    pub metrics: Arc<crate::observability::RuntimeMetrics>,
    pub active_tools: Vec<ToolDefinition>,
    pub default_model_tier: ModelTier,
}

#[derive(Debug, Clone)]
pub struct SubagentSpawnSpec {
    pub subagent_name: String,
    pub task_id: String,
    pub prompt: String,
    pub mode: base::ast::SubagentMode,
    pub requested_ttl_secs: u64,
    pub child_lattice: Option<permissions::attenuation::PermissionLattice>,
}


#[async_trait]
pub trait AgentMiddleware: Send + Sync {
    fn name(&self) -> &'static str;

    fn canonical_slot(&self) -> Option<u8> {
        None
    }

    fn tools(&self) -> Vec<ToolDefinition> {
        Vec::new()
    }

    async fn before_agent(
        &self,
        _state: &mut TantryState,
        _ctx: &TurnExecutionContext,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    async fn wrap_model_call<'a>(
        &'a self,
        state: &'a mut TantryState,
        req: ModelRequest,
        _ctx: &'a TurnExecutionContext,
        next: NextModelCall<'a>,
    ) -> Result<ModelResponse, RuntimeError> {
        next(state, req).await
    }

    async fn evaluate_tool_permission(
        &self,
        _state: &TantryState,
        _tool_use_id: &ToolCallId,
        _tool_name: &str,
        _tool_input: &serde_json::Value,
        _ctx: &TurnExecutionContext,
    ) -> Result<Option<PermissionMode>, RuntimeError> {
        Ok(None)
    }

    async fn execute_tool(
        &self,
        _state: &mut TantryState,
        _tool_use_id: &ToolCallId,
        _tool_name: &str,
        _tool_input: &serde_json::Value,
        _ctx: &TurnExecutionContext,
    ) -> Result<Option<ToolExecutionOutput>, RuntimeError> {
        Ok(None)
    }

    async fn after_agent(
        &self,
        _state: &mut TantryState,
        _ctx: &TurnExecutionContext,
    ) -> Result<LoopDirective, RuntimeError> {
        Ok(LoopDirective::FinishTurn)
    }
}
