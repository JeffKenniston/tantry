use base::execution::StreamEvent;
use transport::backpressure::{CreditControlledPublisher, CreditGrant};

#[test]
fn test_credit_backpressure_coalescing() {
    let mut publisher = CreditControlledPublisher::new(0);

    // Initial state: 0 credits.

    // Publish a delta, it should be held.
    let out1 = publisher.publish_event(StreamEvent::ModelDelta {
        text_delta: "Hello".to_string(),
        reasoning_delta: None,
    });
    assert_eq!(out1.len(), 0);

    // Publish another delta, it should coalesce.
    let out2 = publisher.publish_event(StreamEvent::ModelDelta {
        text_delta: " World".to_string(),
        reasoning_delta: Some("thinking".to_string()),
    });
    assert_eq!(out2.len(), 0);

    // Grant credits
    let flushed = publisher.on_credit_granted(CreditGrant { stream_id: "s1".to_string(), additional_credits: 1 });
    assert!(flushed.is_some());

    if let StreamEvent::ModelDelta { text_delta, reasoning_delta } = flushed.unwrap() {
        assert_eq!(text_delta, "Hello World");
        assert_eq!(reasoning_delta, Some("thinking".to_string()));
    } else {
        panic!("Expected ModelDelta");
    }

    let out3 = publisher.publish_event(StreamEvent::ModelDelta {
        text_delta: "!".to_string(),
        reasoning_delta: Some(" fast".to_string()),
    });
    // we consumed 1 credit, have 0 left
    assert_eq!(out3.len(), 0);
}

#[test]
fn test_lifecycle_preservation() {
    let mut publisher = CreditControlledPublisher::new(0);

    // 0 credits. Hold a delta.
    let out1 = publisher.publish_event(StreamEvent::ModelDelta {
        text_delta: "chunk".to_string(),
        reasoning_delta: None,
    });
    assert_eq!(out1.len(), 0);

    // Publish a lifecycle event. It should immediately flush the held delta, then the lifecycle event.
    // wait, publish_event handles returning the events directly without an async channel
    let out2 = publisher.publish_event(StreamEvent::ToolCallStart {
        tool_use_id: "id1".to_string(),
        name: "tool1".to_string(),
    });

    // Lifecycle events flush coalesced immediately, and if credits == 0, it buffers itself
    // So out2 should be the delta, and the tool call should be pending
    assert_eq!(out2.len(), 1);

    if let StreamEvent::ModelDelta { text_delta, .. } = &out2[0] {
        assert_eq!(text_delta, "chunk");
    } else {
        panic!("Expected ModelDelta");
    }
}
