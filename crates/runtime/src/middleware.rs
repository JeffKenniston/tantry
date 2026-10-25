use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use base::ast::ToolCallId;
use base::execution::{LoopDirective, ToolDefinition};
use base::state::TantryState;
use backends::traits::VfsBackend;
use cognitive::cascade::LlmProvider;
use base::execution::{ModelRequest, ModelResponse};
use data::DataStoreManager;
use iam::IdentityManager;
use permissions::attenuation::PermissionLattice;
use permissions::lattice::PermissionMode;
use transport::backpressure::CreditControlledPublisher;

use crate::error::RuntimeError;

/// Boxed async continuation representing the inner layers of the Phase 2 `wrap_model_call` onion.
pub type NextModelCall<'a> = Box<
    dyn FnOnce(&'a mut TantryState, ModelRequest) -> Pin<
            Box<dyn Future<Output = Result<ModelResponse, RuntimeError>> + Send + 'a>,
        > + Send
        + 'a,
>;

/// Shared runtime services passed to every middleware hook during a turn.
#[derive(Clone)]
pub struct TurnExecutionContext {
    /// Task ID.
    pub task_id: String,
    /// Tenant ID.
    pub tenant_id: String,
    /// IAM manager.
    pub iam: Arc<dyn IdentityManager>,
    /// Permission lattice.
    pub permission_lattice: Arc<PermissionLattice>,
    /// Data stores.
    pub data_stores: Arc<DataStoreManager>,
    /// Backend.
    pub backend: Arc<dyn VfsBackend>,
    /// LLM Provider.
    pub llm_provider: Arc<dyn LlmProvider>,
    /// Credit-controlled publisher (optional).
    pub publisher: Option<Arc<CreditControlledPublisher>>,
    /// Active tools.
    pub active_tools: Vec<ToolDefinition>,
}

/// The AgentMiddleware trait orchestrating the runtime.
#[async_trait]
pub trait AgentMiddleware: Send + Sync {
    /// Canonical middleware name (e.g., "FilesystemMiddleware", "SummarizationMiddleware").
    fn name(&self) -> &'static str;

    /// Canonical slot number (1..=17) for built-in middlewares; `None` for custom Zone 2 middlewares.
    fn canonical_slot(&self) -> Option<u8> {
        None
    }

    /// Tool schemas contributed by this middleware slot.
    fn tools(&self) -> Vec<ToolDefinition> {
        Vec::new()
    }

    /// Phase 1: Executed in forward slot order (1 -> 17) at the start of a turn.
    async fn before_agent(
        &self,
        _state: &mut TantryState,
        _ctx: &TurnExecutionContext,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    /// Phase 2: Executed as a nested onion (1 -> 17 -> LlmProvider -> 17 -> 1).
    async fn wrap_model_call<'a>(
        &'a self,
        state: &'a mut TantryState,
        req: ModelRequest,
        _ctx: &'a TurnExecutionContext,
        next: NextModelCall<'a>,
    ) -> Result<ModelResponse, RuntimeError> {
        next(state, req).await
    }

    /// Phase 3 Hook (Slot 16 `HumanInTheLoopAndAuditMiddleware`):
    /// Evaluates a tool call against the 4D `PermissionLattice` (respecting `HitlBypassSlot`)
    /// and appends an immutable blake3 + MMR entry to `audit_log.sqlite`.
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

    /// Phase 5: Executed in reverse slot order (17 -> 1) when the assistant emits no `ToolUse` blocks.
    async fn after_agent(
        &self,
        _state: &mut TantryState,
        _ctx: &TurnExecutionContext,
    ) -> Result<LoopDirective, RuntimeError> {
        Ok(LoopDirective::FinishTurn)
    }
}
