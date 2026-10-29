use crate::billing::BudgetLeaseGuard;
use crate::error::CognitiveError;
use base::execution::{ModelRequest, ModelResponse, ModelTier, StreamEvent};
use futures::Stream;
use futures::stream::StreamExt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

/// LlmProvider trait
pub type StreamEventResult = Result<StreamEvent, CognitiveError>;
pub type PinnedStream = Pin<Box<dyn Stream<Item = StreamEventResult> + Send>>;

pub trait LlmProvider: Send + Sync {
    /// complete method
    fn complete(&self, req: ModelRequest) -> Result<ModelResponse, CognitiveError>;
    /// stream_complete method
    fn stream_complete(
        &self,
        req: ModelRequest,
    ) -> Result<
        Pin<Box<dyn Stream<Item = Result<StreamEvent, CognitiveError>> + Send>>,
        CognitiveError,
    >;
}

/// SpeculativeCascadeVerifier
/// Verifier for speculative cascading execution.
pub struct SpeculativeCascadeVerifier {
    /// provider
    /// The underlying LLM provider.
    pub provider: Box<dyn LlmProvider>,
}

impl SpeculativeCascadeVerifier {
    /// verify_stream
    pub async fn verify_stream(
        &self,
        req: ModelRequest,
        guard: Arc<Mutex<BudgetLeaseGuard>>,
        target_tier: ModelTier,
    ) -> Result<
        Pin<Box<dyn Stream<Item = Result<StreamEvent, CognitiveError>> + Send>>,
        CognitiveError,
    > {
        let mut stream = self.provider.stream_complete(req.clone())?;

        let mut tokens_checked = 0;
        let mut first_events = Vec::new();
        let mut needs_escalation = false;

        let mut check_buffer = String::new();

        while let Some(res) = stream.next().await {
            match res {
                Ok(event) => {
                    if let StreamEvent::ModelDelta { ref text_delta, .. } = event {
                        tokens_checked += 1;
                        check_buffer.push_str(text_delta);

                        let mut has_malformed = false;
                        #[allow(clippy::collapsible_if)]
                        if check_buffer.contains("```json\n{\n") {
                            #[allow(clippy::collapsible_if)]
                            if tokens_checked >= 64 {
                                if let Some(start) = check_buffer.find("```json\n") {
                                    let content = &check_buffer[start + 8..];

                                    // Parse iteratively rather than using the naive trailing } logic
                                    // that breaks on nested JSON braces.
                                    let mut braces = 0;
                                    let mut in_string = false;
                                    let mut is_escaped = false;
                                    let mut found_end = false;
                                    let mut parse_end_idx = 0;

                                    for (i, c) in content.char_indices() {
                                        if !in_string {
                                            if c == '{' {
                                                braces += 1;
                                            } else if c == '}' {
                                                braces -= 1;
                                                if braces == 0 {
                                                    found_end = true;
                                                    // Move past the '}'
                                                    parse_end_idx = i + 1;
                                                    break;
                                                }
                                            } else if c == '"' {
                                                in_string = true;
                                            }
                                        } else {
                                            if c == '"' && !is_escaped {
                                                in_string = false;
                                            } else {
                                                is_escaped = c == '\\' && !is_escaped;
                                            }
                                        }
                                    }

                                    if found_end {
                                        let json_str = &content[..parse_end_idx];
                                        if serde_json::from_str::<serde_json::Value>(json_str)
                                            .is_err()
                                        {
                                            has_malformed = true;
                                        }
                                    }
                                }
                            }
                        }

                        if has_malformed {
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
                let _g = guard.clone();
                res
            });
            return Ok(Box::pin(mapped_stream));
        }

        let remaining_stream = futures::stream::iter(first_events)
            .chain(stream)
            .map(move |res| {
                let _g = guard.clone();
                res
            });
        Ok(Box::pin(remaining_stream))
    }
}
