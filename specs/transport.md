## 9. Crate 8: `crates/transport` (Zenoh 1.10.1 Mesh, Quinn QUIC/H3 MCP `2026-07-28` & Credit Backpressure)

### Crate `transport`: Phase 1 — Hybrid PQ Wire Envelopes & Credit-Based Adaptive Backpressure
1. **`src/envelope.rs` (Hybrid Post-Quantum Wire Envelope)**:
   * `WireEnvelope`: `envelope_id: Uuid`, `sender_spiffe_id: String`, `traceparent: String`, `timestamp_ms: i64`, `payload_bytes: Bytes`, `ed25519_sig: Vec<u8>` (64B), `mldsa65_sig: Option<Vec<u8>>` (3309B).
   * Signs and verifies `BLAKE3("tantry:wire-env:v3" || envelope_id || sender_spiffe_id || traceparent || timestamp_ms_be64 || payload_bytes)`. Rejects any envelope missing a valid `mldsa65_sig` when `require_pq_hybrid_signatures = true`.
2. **`src/backpressure.rs` (Credit-Controlled Stream Publisher & Coalescing Buffer)**:
   * `CreditGrant`: `stream_id: String`, `additional_credits: u32`.
   * `CreditControlledPublisher`: Tracks available credits via `AtomicU32`.
     * Whenever `credits > 0`, decrements credit by 1 and flushes the next event immediately.
     * Whenever `credits == 0`, holds a pending `Option<StreamEvent::ModelDelta>` slot and coalesces incoming `StreamEvent::ModelDelta` chunks in-place (`text_delta.push_str`, `reasoning_delta` append).
     * **Lifecycle Preservation Invariant**: Lifecycle events (`ToolCallStart`, `ToolCallEnd`, `Interrupted`, `TurnComplete`) NEVER coalesce or drop; if a lifecycle event arrives while a coalesced `ModelDelta` is buffered, flushes the coalesced `ModelDelta` immediately before queuing the lifecycle event.

### Crate `transport`: Phase 2 — `ZenohBusTransport` (`zenoh 1.10.1`, `src/zenoh_bus.rs`)
1. **Canonical Key Expressions & Topic Guard**:
   * Command Queryable: `tantry/{trust_domain}/subagents/{subagent_name}/tasks/{task_id}/cmd`
   * Live Event Pub/Sub: `tantry/{trust_domain}/subagents/{subagent_name}/tasks/{task_id}/events`
   * State Snapshot Queryable: `tantry/{trust_domain}/subagents/{subagent_name}/tasks/{task_id}/state`
   * Every publish and subscribe call invokes `permissions::zenoh_guard::evaluate_zenoh_topic` before interacting with the Zenoh session.
2. **Termux & Localhost UDS Fast-Path**:
   * For co-located subagents on the same host or inside Termux, automatically binds `unixsock-stream/${PREFIX}/var/run/tantry/zenoh-{task_id}.sock`; for remote peers, configures `zenoh 1.10.1` TLS/QUIC locators using SPIFFE X.509-SVID mTLS.

### Crate `transport`: Phase 3 — `QuicMcpTransport` (MCP `2026-07-28` + 250ms H2 Fallback) & `AgentProtocolHttpTransport`
1. **`src/quic_mcp.rs` (Patched Quinn QUIC/H3 + 250ms Silent HTTP/2 Fallback)**:
   * Enforces `quinn 0.11.12` (`quinn-proto >= 0.11.18`) and strictly uses ordered stream reads (`RecvStream::read` / `read_to_end`; **`read_unordered` is forbidden** per `RUSTSEC-2026-0338`).
   * **Happy-Eyeballs 250ms Race**: Races the UDP QUIC/H3 connection handshake against `tokio::time::sleep(Duration::from_millis(quic_handshake_fallback_timeout_ms))` (`250ms`). If UDP is blackholed, fails, or times out, cancels the QUIC attempt and connects via TLS 1.3 over TCP HTTP/2 (`reqwest` / `h2`), caching the winning transport protocol per endpoint in `DashMap<SocketAddr, (McpWireProtocol, Instant)>` for `300s`.
   * **MCP `2026-07-28` Wire & Security Invariants**:
     * Attaches mandatory headers on every request: `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method: <jsonrpc_method>`, `Mcp-Name: <target_tool_or_resource_name>` (SEP-2243), and `Accept: application/json, text/event-stream`.
     * **Anti-Token-Passthrough Guard**: Never forwards an inbound client's `Authorization` header to an upstream MCP server; always mints a fresh audience-scoped outbound token + RFC 9449 `DPoP` proof (`mint_dpop_proof`).
     * Injects `_meta: {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "traceparent": ..., "tracestate": ..., "baggage": ...}` (SEP-414) into every JSON-RPC params object.
     * Supports `server/discover`, SEP-2322 `InputRequiredResult` multi-round-trip pause/resume, SEP-2549 resource caching (`ttlMs`, `cacheScope`), and bidirectional server-to-client `sampling/createMessage` and `elicitation/create`.
2. **`src/http_ap.rs` (`AgentProtocolHttpTransport`)**:
   * Implements Agent Protocol REST + SSE endpoints (`POST /threads`, `POST /threads/{thread_id}/runs`, `GET /threads/{thread_id}/runs/{run_id}`, `POST /threads/{thread_id}/runs/{run_id}/cancel`, and SSE stream via `eventsource-stream`).

---
