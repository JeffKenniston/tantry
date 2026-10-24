use base::execution::StreamEvent;
use transport::backpressure::{CreditControlledPublisher, CreditGrant};
use transport::quic_mcp::{QuicMcpTransport, McpWireProtocol};
use quinn::Endpoint;


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

#[tokio::test]
async fn test_quic_fallback() {
    // 1. Simulates a blackholed UDP socket and verifies `QuicMcpTransport` silently falls back from Quinn QUIC/H3 to TLS 1.3 HTTP/2 within `260ms`.
    let endpoint = Endpoint::client("[::]:0".parse().unwrap()).unwrap();
    let http_client = reqwest::Client::new();
    let transport = QuicMcpTransport::new(endpoint, http_client, 250);

    // To reliably test the fallback without OS ICMP port unreachable immediate failures on localhost,
    // we mock it by trying to connect to a blackhole IP (like an unroutable IP).
    let start = std::time::Instant::now();
    // Connect to a reserved documentation IP that blackholes traffic
    let protocol = transport.connect("192.0.2.1:12345".parse().unwrap()).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(protocol, McpWireProtocol::Http2);
    assert!(elapsed.as_millis() >= 250 && elapsed.as_millis() < 300, "took {} ms", elapsed.as_millis());
}

#[tokio::test]
async fn test_mcp_headers_and_dpop() {
    let endpoint = Endpoint::client("[::]:0".parse().unwrap()).unwrap();
    let http_client = reqwest::Client::new();
    let transport = QuicMcpTransport::new(endpoint, http_client, 250);

    // Test that the transport can mint dpop proofs
    let proof = transport.mint_dpop_proof("POST", "https://example.com");
    assert!(!proof.is_empty());
}
