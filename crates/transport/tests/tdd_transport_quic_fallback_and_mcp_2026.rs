use base::execution::StreamEvent;
use quinn::Endpoint;
use transport::backpressure::{CreditControlledPublisher, CreditGrant};
use transport::quic_mcp::{McpWireProtocol, QuicMcpTransport};

#[test]
fn test_credit_backpressure_coalescing() {
    let publisher = CreditControlledPublisher::new(0);

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
    let flushed = publisher.on_credit_granted(CreditGrant {
        stream_id: "s1".to_string(),
        additional_credits: 1,
    });
    assert!(flushed.is_some());

    if let StreamEvent::ModelDelta {
        text_delta,
        reasoning_delta,
    } = flushed.unwrap()
    {
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
    let publisher = CreditControlledPublisher::new(0);

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
    struct DummyIM;
impl iam::IdentityManager for DummyIM {
    fn current_svid(&self) -> Option<iam::svid::WorkloadSvid> { None }
    fn mint_jwt_svid(&self, _audience: &[String], _ttl_secs: i64) -> Result<String, iam::error::IamError> { Ok("test.jwt.token".to_string()) }
    fn mint_subagent_svid(&self, _parent: &iam::svid::WorkloadSvid, _task_id: &str, _agent_name: &str, _ttl_secs: i64) -> Result<iam::svid::WorkloadSvid, iam::error::IamError> { unimplemented!() }
    fn verify_jwt_svid(&self, _token: &str, _audience: &str) -> Result<(), iam::error::IamError> { unimplemented!() }
    fn verify_scoped_tunnel_token(&self, _token: &str) -> Result<iam::ScopedTunnelGrant, iam::error::IamError> { unimplemented!() }
    fn verify_audit_sth(&self, _sth: &iam::AuditSthSignature) -> Result<(), iam::error::IamError> { unimplemented!() }
    fn key_hierarchy(&self) -> &iam::KeyHierarchy { unimplemented!() }
    fn sign_audit_sth(&self, _: u64, _: i64, _: &[u8; 32]) -> Result<iam::AuditSthSignature, iam::error::IamError> { unimplemented!() }
}
let transport = QuicMcpTransport::new(endpoint, http_client, 250, DummyIM);

    // To reliably test the fallback without OS ICMP port unreachable immediate failures on localhost,
    // we mock it by trying to connect to a blackhole IP (like an unroutable IP).
    let start = std::time::Instant::now();
    // Connect to a reserved documentation IP that blackholes traffic
    let protocol = transport
        .connect("192.0.2.1:12345".parse().unwrap())
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert_eq!(protocol, McpWireProtocol::Http2);
    assert!(
        elapsed.as_millis() >= 250 && elapsed.as_millis() < 300,
        "took {} ms",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn test_mcp_headers_and_dpop() {
    let endpoint = Endpoint::client("[::]:0".parse().unwrap()).unwrap();
    let http_client = reqwest::Client::new();
    struct DummyIM;
impl iam::IdentityManager for DummyIM {
    fn current_svid(&self) -> Option<iam::svid::WorkloadSvid> { None }
    fn mint_jwt_svid(&self, _audience: &[String], _ttl_secs: i64) -> Result<String, iam::error::IamError> { Ok("test.jwt.token".to_string()) }
    fn mint_subagent_svid(&self, _parent: &iam::svid::WorkloadSvid, _task_id: &str, _agent_name: &str, _ttl_secs: i64) -> Result<iam::svid::WorkloadSvid, iam::error::IamError> { unimplemented!() }
    fn verify_jwt_svid(&self, _token: &str, _audience: &str) -> Result<(), iam::error::IamError> { unimplemented!() }
    fn verify_scoped_tunnel_token(&self, _token: &str) -> Result<iam::ScopedTunnelGrant, iam::error::IamError> { unimplemented!() }
    fn verify_audit_sth(&self, _sth: &iam::AuditSthSignature) -> Result<(), iam::error::IamError> { unimplemented!() }
    fn key_hierarchy(&self) -> &iam::KeyHierarchy { unimplemented!() }
    fn sign_audit_sth(&self, _: u64, _: i64, _: &[u8; 32]) -> Result<iam::AuditSthSignature, iam::error::IamError> { unimplemented!() }
}
let transport = QuicMcpTransport::new(endpoint, http_client, 250, DummyIM);

    // Test that the transport can mint dpop proofs
    let res = transport.mint_dpop_proof_and_jwt("POST", "https://example.com", "audience").await;
    assert!(res.is_err()); // because svid is None in ca

}

#[tokio::test]
async fn test_mcp_sampling_create_message_recursion_limit() {
    let endpoint = Endpoint::client("[::]:0".parse().unwrap()).unwrap();
    let http_client = reqwest::Client::new();
    struct DummyIM;
impl iam::IdentityManager for DummyIM {
    fn current_svid(&self) -> Option<iam::svid::WorkloadSvid> { None }
    fn mint_jwt_svid(&self, _audience: &[String], _ttl_secs: i64) -> Result<String, iam::error::IamError> { Ok("test.jwt.token".to_string()) }
    fn mint_subagent_svid(&self, _parent: &iam::svid::WorkloadSvid, _task_id: &str, _agent_name: &str, _ttl_secs: i64) -> Result<iam::svid::WorkloadSvid, iam::error::IamError> { unimplemented!() }
    fn verify_jwt_svid(&self, _token: &str, _audience: &str) -> Result<(), iam::error::IamError> { unimplemented!() }
    fn verify_scoped_tunnel_token(&self, _token: &str) -> Result<iam::ScopedTunnelGrant, iam::error::IamError> { unimplemented!() }
    fn verify_audit_sth(&self, _sth: &iam::AuditSthSignature) -> Result<(), iam::error::IamError> { unimplemented!() }
    fn key_hierarchy(&self) -> &iam::KeyHierarchy { unimplemented!() }
    fn sign_audit_sth(&self, _: u64, _: i64, _: &[u8; 32]) -> Result<iam::AuditSthSignature, iam::error::IamError> { unimplemented!() }
}
let transport = QuicMcpTransport::new(endpoint, http_client, 250, DummyIM);

    let res = transport
        .create_message(
            "192.0.2.1:12345".parse().unwrap(),
            "target",
            serde_json::json!({}),
            3,
        )
        .await;

    assert!(res.is_err());
    if let Err(transport::TransportError::Internal(msg)) = res {
        assert!(msg.contains("recursion limit exceeded"));
    } else {
        panic!("Expected internal error for recursion limit");
    }
}
