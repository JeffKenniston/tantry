pub mod router;
pub mod tokenizer;
pub mod semantic_cache;
pub mod billing;
pub mod error;
pub mod cascade;

use base::execution::{ModelRequest, ModelResponse};
use base::state::TantryState;
use base::ast::McpSamplingDepthSlot;
use data::task_ledger::TaskLedgerStore;
use std::sync::{Arc, Mutex};
use rusqlite::Connection;
use crate::error::CognitiveError;

/// execute_mcp_sampling_request fn
pub fn execute_mcp_sampling_request(
    state: &mut TantryState,
    task_id: &str,
    lease_micros: i64,
    req: ModelRequest,
    provider: &dyn cascade::LlmProvider,
    conn: Arc<Mutex<Connection>>,
) -> Result<ModelResponse, CognitiveError> {
    let mut depth: u32 = 0;
    if let Some(slot) = state.extensions.get::<McpSamplingDepthSlot>() {
        depth = slot.depth;
    }
    
    if depth >= 2 {
        return Err(CognitiveError::McpSamplingRecursionLimitExceeded(depth));
    }
    
    state.extensions.insert(McpSamplingDepthSlot { depth: depth + 1 });
    
    let ledger_store = Arc::new(TaskLedgerStore::new(conn));
    let guard = crate::billing::BillingEnforcer::new(ledger_store).acquire_lease_fixed(task_id, lease_micros)?;

    let res = provider.complete(req);
    
    if res.is_ok() {
        let _ = guard.settle(0, 0, 0, 0, 0, 0, None, 0, None);
    }
    
    res
}
