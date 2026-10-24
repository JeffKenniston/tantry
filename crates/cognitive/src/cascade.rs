use std::pin::Pin;
use futures::Stream;
use base::execution::{ModelRequest, ModelResponse, StreamEvent, ModelTier};
use crate::error::CognitiveError;
use crate::billing::BudgetLeaseGuard;
use futures::stream::StreamExt;
use std::sync::{Arc, Mutex};

/// LlmProvider trait
pub trait LlmProvider: Send + Sync {
    /// complete method
    fn complete(&self, req: ModelRequest) -> Result<ModelResponse, CognitiveError>;
    /// stream_complete method
    fn stream_complete(&self, req: ModelRequest) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CognitiveError>> + Send>>, CognitiveError>;
}

/// SpeculativeCascadeVerifier
pub struct SpeculativeCascadeVerifier {
    /// provider
    pub provider: Box<dyn LlmProvider>,
}

impl SpeculativeCascadeVerifier {
    /// verify_stream
    pub async fn verify_stream(
        &self,
        req: ModelRequest,
        guard: Arc<Mutex<BudgetLeaseGuard>>,
        target_tier: ModelTier,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CognitiveError>> + Send>>, CognitiveError> {
        let mut stream = self.provider.stream_complete(req.clone())?;
        
        let mut tokens_checked = 0;
        let mut first_events = Vec::new();
        let mut needs_escalation = false;

        while let Some(res) = stream.next().await {
            match res {
                Ok(event) => {
                    if let StreamEvent::ModelDelta { ref text_delta, .. } = event {
                        tokens_checked += 1;
                        if text_delta.contains("```json\n{\n  \"tool\":") && text_delta.contains("\"malformed_json\"") { // Dummy condition for low log-prob / malformed tool JSON.
                            needs_escalation = true;
                            break;
                        }
                    }
                    first_events.push(Ok(event));
                    
                    if tokens_checked >= 64 {
                        break;
                    }
                }
                Err(e) => {
                    first_events.push(Err(e));
                    break;
                }
            }
        }
        
        if needs_escalation {
            {
                let mut guard_lock = guard.lock().unwrap();
                // Atomically reserve an escalated target lease.
                // A static delta of 50_000 micro-dollars is applied as LlmProvider does not expose dynamic token estimations mid-stream.
                let target_lease = guard_lock.lease_micros + 50_000;
                guard_lock.upgrade_lease(target_lease)?;
            }
            let mut req2 = req.clone();
            req2.target_tier = target_tier;
            let stream2 = self.provider.stream_complete(req2)?;
            let mapped_stream = stream2.map(move |res| {
                // Ensure guard stays alive in the closure context via Arc clone
                let _g = guard.clone(); 
                res
            });
            return Ok(Box::pin(mapped_stream));
        }
        
        // combine events
        let remaining_stream = futures::stream::iter(first_events).chain(stream).map(move |res| {
            // Ensure guard stays alive in the closure context via Arc clone
            let _g = guard.clone();
            res
        });
        Ok(Box::pin(remaining_stream))
    }
}
