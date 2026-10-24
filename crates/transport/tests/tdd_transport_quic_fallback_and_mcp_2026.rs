use base::execution::StreamEvent;
use transport::backpressure::CreditControlledPublisher;
use tokio::sync::mpsc;
use std::time::Duration;

#[tokio::test]
async fn test_credit_backpressure_coalescing() {
    let (tx, mut rx) = mpsc::channel(100);
    let mut publisher = CreditControlledPublisher::new(tx);

    // Initial state: 0 credits.

    // Publish a delta, it should be held.
    publisher.publish(StreamEvent::ModelDelta {
        text_delta: "Hello".to_string(),
        reasoning_delta: None,
    }).await.unwrap();

    assert!(tokio::time::timeout(Duration::from_millis(10), rx.recv()).await.is_err());

    // Publish another delta, it should coalesce.
    publisher.publish(StreamEvent::ModelDelta {
        text_delta: " World".to_string(),
        reasoning_delta: Some("thinking".to_string()),
    }).await.unwrap();

    assert!(tokio::time::timeout(Duration::from_millis(10), rx.recv()).await.is_err());

    // Grant credits
    publisher.grant_credits(1);

    // Since we don't actively poll in `grant_credits`, it won't flush until the next publish or flush call.
    // Let's publish another delta. It should coalesce, then we consume a credit and flush.
    publisher.publish(StreamEvent::ModelDelta {
        text_delta: "!".to_string(),
        reasoning_delta: Some(" fast".to_string()),
    }).await.unwrap();

    let event = rx.recv().await.unwrap();
    if let StreamEvent::ModelDelta { text_delta, reasoning_delta } = event {
        assert_eq!(text_delta, "Hello World!");
        assert_eq!(reasoning_delta, Some("thinking fast".to_string()));
    } else {
        panic!("Expected ModelDelta");
    }
}

#[tokio::test]
async fn test_lifecycle_preservation() {
    let (tx, mut rx) = mpsc::channel(100);
    let mut publisher = CreditControlledPublisher::new(tx);

    // 0 credits. Hold a delta.
    publisher.publish(StreamEvent::ModelDelta {
        text_delta: "chunk".to_string(),
        reasoning_delta: None,
    }).await.unwrap();

    // Publish a lifecycle event. It should immediately flush the held delta, then the lifecycle event.
    publisher.publish(StreamEvent::ToolCallStart {
        tool_use_id: "id1".to_string(),
        name: "tool1".to_string(),
    }).await.unwrap();

    let ev1 = rx.recv().await.unwrap();
    if let StreamEvent::ModelDelta { text_delta, .. } = ev1 {
        assert_eq!(text_delta, "chunk");
    } else {
        panic!("Expected ModelDelta");
    }

    let ev2 = rx.recv().await.unwrap();
    if let StreamEvent::ToolCallStart { tool_use_id, .. } = ev2 {
        assert_eq!(tool_use_id, "id1");
    } else {
        panic!("Expected ToolCallStart");
    }
}
