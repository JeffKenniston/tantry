use base::execution::StreamEvent;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Credit-Controlled Stream Publisher & Coalescing Buffer
/// A struct representing a grant of credits from the consumer to the publisher.
pub struct CreditGrant {
    /// The stream identifier.
    pub stream_id: String,
    /// The number of additional credits granted.
    pub additional_credits: u32,
}

/// A publisher that tracks credits and coalesces ModelDelta events when credits are exhausted.
pub struct CreditControlledPublisher {
    /// The current number of available credits.
    pub credits: Arc<AtomicU32>,
    /// The pending StreamEvent slot for coalescing ModelDelta events.
    pub pending: Option<StreamEvent>,
}

impl CreditControlledPublisher {
    /// Creates a new CreditControlledPublisher with the specified initial credits.
    pub fn new(initial_credits: u32) -> Self {
        Self {
            credits: Arc::new(AtomicU32::new(initial_credits)),
            pending: None,
        }
    }

    /// Flushes any pending event if credits are available.
    pub fn flush(&mut self) -> Option<StreamEvent> {
        let current_credits = self.credits.load(Ordering::SeqCst);
        if current_credits > 0 && self.pending.is_some() {
            if self.credits.fetch_sub(1, Ordering::SeqCst) > 0 {
                return self.pending.take();
            } else {
                self.credits.fetch_add(1, Ordering::SeqCst);
            }
        }
        None
    }

    /// Grants additional credits to the publisher and flushes any pending coalesced event.
    pub fn on_credit_granted(&mut self, grant: CreditGrant) -> Option<StreamEvent> {
        self.credits
            .fetch_add(grant.additional_credits, Ordering::SeqCst);
        self.flush()
    }

    /// Attempts to publish an event.
    /// Returns a list of events that should be sent out immediately.
    pub fn publish_event(&mut self, event: StreamEvent) -> Vec<StreamEvent> {
        let mut out = Vec::<StreamEvent>::new();
        let is_lifecycle = !matches!(event, StreamEvent::ModelDelta { .. });

        if is_lifecycle {
            // Lifecycle events flush any pending coalesced ModelDelta first.
            if let Some(pending_delta) = self.pending.take() {
                if self.credits.load(Ordering::SeqCst) > 0 {
                    self.credits.fetch_sub(1, Ordering::SeqCst);
                }
                out.push(pending_delta);
            }

            // Now handle the lifecycle event
            if self.credits.load(Ordering::SeqCst) > 0 {
                self.credits.fetch_sub(1, Ordering::SeqCst);
                out.push(event);
            } else {
                self.pending = Some(event);
            }
        } else {
            // ModelDelta
            if self.credits.load(Ordering::SeqCst) > 0 && self.pending.is_none() {
                self.credits.fetch_sub(1, Ordering::SeqCst);
                out.push(event);
            } else if self.credits.load(Ordering::SeqCst) > 0 {
                // If credits > 0 but we have a pending event, flush the pending one,
                // consume credit, and process this event recursively or put it out.
                // Actually `flush()` does this, but we'll do it manually.
                let pending_ev = self.pending.take().unwrap();
                self.credits.fetch_sub(1, Ordering::SeqCst);
                out.push(pending_ev);

                if self.credits.load(Ordering::SeqCst) > 0 {
                    self.credits.fetch_sub(1, Ordering::SeqCst);
                    out.push(event);
                } else {
                    self.pending = Some(event);
                }
            } else {
                // Credits == 0
                if let Some(ref mut pending) = self.pending {
                    // Try to coalesce in place
                    let res = pending.coalesce_in_place(event);
                    if let Err(uncoalesced) = res {
                        // This implies `pending` was a lifecycle event.
                        // But lifecycle events should never be pending if a delta comes in
                        // because lifecycle events don't coalesce. If one is pending, flush it
                        // immediately (without credit) and buffer the ModelDelta?
                        // "Lifecycle events NEVER coalesce or drop; if a lifecycle event arrives while a coalesced ModelDelta is buffered, flushes the coalesced ModelDelta immediately before queuing the lifecycle event."
                        // It does NOT say lifecycle events wait for credit. It says they flush the coalesced delta.
                        let pending_lifecycle = self.pending.take().unwrap();
                        out.push(pending_lifecycle);
                        self.pending = Some(uncoalesced);
                    }
                } else {
                    self.pending = Some(event);
                }
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::execution::TokenUsage;

    #[test]
    fn test_credit_exhaustion_and_coalescing() {
        let mut publisher = CreditControlledPublisher::new(1);

        let e1 = StreamEvent::ModelDelta {
            text_delta: "A".to_string(),
            reasoning_delta: None,
        };
        let out1 = publisher.publish_event(e1);
        assert_eq!(out1.len(), 1);

        let e2 = StreamEvent::ModelDelta {
            text_delta: "B".to_string(),
            reasoning_delta: None,
        };
        let out2 = publisher.publish_event(e2);
        assert_eq!(out2.len(), 0); // Credit exhausted, buffered

        let e3 = StreamEvent::ModelDelta {
            text_delta: "C".to_string(),
            reasoning_delta: Some("R1".to_string()),
        };
        let out3 = publisher.publish_event(e3);
        assert_eq!(out3.len(), 0); // Coalesced

        if let Some(StreamEvent::ModelDelta {
            text_delta,
            reasoning_delta,
        }) = &publisher.pending
        {
            assert_eq!(text_delta, "BC");
            assert_eq!(reasoning_delta.as_ref().unwrap(), "R1");
        } else {
            panic!("Expected coalesced pending delta");
        }

        let flush_res = publisher.on_credit_granted(CreditGrant {
            stream_id: "s1".to_string(),
            additional_credits: 1,
        });
        assert!(flush_res.is_some());

        if let StreamEvent::ModelDelta { text_delta, .. } = flush_res.unwrap() {
            assert_eq!(text_delta, "BC");
        } else {
            panic!("Expected ModelDelta");
        }

        assert!(publisher.pending.is_none());
        assert_eq!(publisher.credits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_lifecycle_events_flush_pending_delta() {
        let mut publisher = CreditControlledPublisher::new(0);

        let e1 = StreamEvent::ModelDelta {
            text_delta: "A".to_string(),
            reasoning_delta: None,
        };
        let out1 = publisher.publish_event(e1);
        assert_eq!(out1.len(), 0);

        let lifecycle = StreamEvent::TurnComplete {
            step_index: 1,
            usage: TokenUsage {
                input_tokens: 0,
                cached_tokens: 0,
                output_tokens: 0,
            },
        };
        let out2 = publisher.publish_event(lifecycle);

        // Lifecycle arrives while delta is buffered. It should force-flush the pending delta.
        // It returns the pending delta. Wait, what about the lifecycle event itself?
        // It should buffer it if no credits are available.
        assert_eq!(out2.len(), 1);
        if let StreamEvent::ModelDelta { text_delta, .. } = &out2[0] {
            assert_eq!(text_delta, "A");
        } else {
            panic!("Expected forced flush of ModelDelta");
        }

        assert!(publisher.pending.is_some());
        if let StreamEvent::TurnComplete { .. } = publisher.pending.as_ref().unwrap() {
        } else {
            panic!("Expected TurnComplete buffered");
        }
    }
}
