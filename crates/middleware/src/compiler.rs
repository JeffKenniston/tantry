use runtime::middleware::{AgentMiddleware, NextModelCall, TurnExecutionContext};
use runtime::error::RuntimeError;
use std::sync::Arc;
use std::collections::BTreeSet;

pub const SLOT1_IDENTITY_AND_BUDGET: &str = "IdentityAndBudgetMiddleware";
pub const SLOT2_TODO_LIST: &str = "TodoListMiddleware";
pub const SLOT3_FILESYSTEM: &str = "FilesystemMiddleware";
pub const SLOT4_REPO_INTELLIGENCE: &str = "RepoIntelligenceMiddleware";
pub const SLOT5_INTERPRETER_AND_SANDBOX: &str = "InterpreterAndSandboxMiddleware";
pub const SLOT6_SKILLS: &str = "SkillsMiddleware";
pub const SLOT7_SUBAGENT: &str = "SubAgentMiddleware";
pub const SLOT8_ASYNC_SUBAGENT: &str = "AsyncSubAgentMiddleware";
pub const SLOT9_SUMMARIZATION: &str = "SummarizationMiddleware";
pub const SLOT10_PATCH_TOOL_CALLS: &str = "PatchToolCallsMiddleware";
pub const SLOT12_COGNITIVE_ROUTER: &str = "CognitiveRouterMiddleware";
pub const SLOT13_PROFILE_FILTER: &str = "ProfileFilterMiddleware";
pub const SLOT14_MEMORY: &str = "MemoryMiddleware";
pub const SLOT15_RUBRIC: &str = "RubricMiddleware";
pub const SLOT16_HITL_AND_AUDIT: &str = "HumanInTheLoopAndAuditMiddleware";
pub const SLOT17_PROMPT_CACHING_AND_MODALITY: &str = "PromptCachingAndModalityMiddleware";

pub struct MiddlewarePipelineCompiler;

impl MiddlewarePipelineCompiler {
    pub fn compile(
        canonical_slots: Vec<Arc<dyn AgentMiddleware>>,
        custom_middlewares: Vec<Arc<dyn AgentMiddleware>>,
        excluded_middleware: &BTreeSet<String>,
    ) -> Result<Vec<Arc<dyn AgentMiddleware>>, RuntimeError> {
        if excluded_middleware.contains(SLOT3_FILESYSTEM) {
            return Err(RuntimeError::MiddlewareError {
                slot_name: SLOT3_FILESYSTEM.to_string(),
                reason: "Mandatory scaffolding middleware 'FilesystemMiddleware' cannot be excluded".to_string(),
            });
        }

        let mut zone1: Vec<Arc<dyn AgentMiddleware>> = canonical_slots
            .iter()
            .filter(|m| matches!(m.canonical_slot(), Some(1..=10)))
            .cloned()
            .collect();
        zone1.sort_by_key(|m| m.canonical_slot().unwrap());

        let mut zone3: Vec<Arc<dyn AgentMiddleware>> = canonical_slots
            .iter()
            .filter(|m| matches!(m.canonical_slot(), Some(12..=17)))
            .cloned()
            .collect();
        zone3.sort_by_key(|m| m.canonical_slot().unwrap());

        let mut zone2: Vec<Arc<dyn AgentMiddleware>> = Vec::new();

        for custom_mw in custom_middlewares {
            let name = custom_mw.name();
            if let Some(idx) = zone1.iter().position(|m| m.name() == name) {
                zone1[idx] = custom_mw;
            } else if let Some(idx) = zone3.iter().position(|m| m.name() == name) {
                zone3[idx] = custom_mw;
            } else if let Some(idx) = zone2.iter().position(|m| m.name() == name) {
                zone2[idx] = custom_mw;
            } else {
                zone2.push(custom_mw);
            }
        }

        let compiled: Vec<Arc<dyn AgentMiddleware>> = zone1
            .into_iter()
            .chain(zone2.into_iter())
            .chain(zone3.into_iter())
            .filter(|m| !excluded_middleware.contains(m.name()))
            .collect();

        if !compiled.iter().any(|m| m.name() == SLOT3_FILESYSTEM) {
            return Err(RuntimeError::MiddlewareError {
                slot_name: SLOT3_FILESYSTEM.to_string(),
                reason: "Mandatory 'FilesystemMiddleware' is missing from compiled pipeline".to_string(),
            });
        }

        Ok(compiled)
    }
}

pub fn build_middleware_onion<'a>(
    middlewares: &'a [Arc<dyn AgentMiddleware>],
    base_call: NextModelCall<'a>,
    ctx: &'a TurnExecutionContext,
) -> NextModelCall<'a> {
    let mut inner = base_call;
    for mw in middlewares.iter().rev() {
        let next = inner;
        inner = Box::new(move |st, r| {
            Box::pin(async move { mw.wrap_model_call(st, r, ctx, next).await })
        });
    }
    inner
}
