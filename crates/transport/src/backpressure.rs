use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use base::execution::StreamEvent;

/// Represents a grant of additional credits for a specific stream.
/// Used to control the flow of messages in a stream, applying backpressure
/// when the consumer is not ready to process more events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditGrant {
    /// The unique identifier of the stream receiving the credits.
    pub stream_id: String,
    /// The number of additional credits to grant to the publisher.
    pub additional_credits: u32,
}

/// A stream publisher that controls the emission of events based on available credits.
/// It buffers and coalesces `ModelDelta` events when credits are exhausted, and flushes
/// them when credits become available or when lifecycle events occur.
pub struct CreditControlledPublisher {
    /// The current number of available credits, tracked atomically.
    credits: Arc<AtomicU32>,
    /// The underlying channel sender to push flushed events into.
    sender: mpsc::Sender<StreamEvent>,
    /// A buffer holding the currently coalesced `ModelDelta` event, if any.
    pending_model_delta: Option<StreamEvent>,
}

impl CreditControlledPublisher {
    /// Constructs a new `CreditControlledPublisher` wrapping the provided sender channel.
    /// Initially starts with zero credits.
    pub fn new(sender: mpsc::Sender<StreamEvent>) -> Self {
        Self {
            credits: Arc::new(AtomicU32::new(0)),
            sender,
            pending_model_delta: None,
        }
    }

    /// Atomically adds new credits to the publisher, allowing it to flush more buffered events.
    pub fn grant_credits(&self, credits: u32) {
        self.credits.fetch_add(credits, Ordering::SeqCst);
    }

    /// Publishes a new event to the stream, respecting available credits and lifecycle invariants.
    pub async fn publish(&mut self, event: StreamEvent) -> Result<(), mpsc::error::SendError<StreamEvent>> {
        let is_lifecycle = !matches!(event, StreamEvent::ModelDelta { .. });

        if is_lifecycle {
            if let Some(pending) = self.pending_model_delta.take() {
                self.sender.send(pending).await?;
            }
            self.sender.send(event).await?;
            return Ok(());
        }

        if self.credits.load(Ordering::SeqCst) > 0 {
            let to_send = if let Some(mut pending) = self.pending_model_delta.take() {
                let _ = pending.coalesce_in_place(event);
                pending
            } else {
                event
            };

            let mut sent = false;
            let mut current = self.credits.load(Ordering::SeqCst);
            while current > 0 {
                if self.credits.compare_exchange_weak(current, current - 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    self.sender.send(to_send.clone()).await?;
                    sent = true;
                    break;
                }
                current = self.credits.load(Ordering::SeqCst);
            }

            if !sent {
                self.pending_model_delta = Some(to_send);
            }
        } else {
            if let Some(mut pending) = self.pending_model_delta.take() {
                let _ = pending.coalesce_in_place(event);
                self.pending_model_delta = Some(pending);
            } else {
                self.pending_model_delta = Some(event);
            }
        }

        Ok(())
    }
}
