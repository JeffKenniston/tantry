## 8. Crate 7: `crates/cognitive` (12D Disjoint LinUCB + Thompson Router, SIMD Semantic Cache & Credit-Lease Gate)

### Crate `cognitive`: Phase 1 — 5-Block KV-Cache Prefix Hasher & 12D Hybrid LinUCB + Thompson Router
1. **`src/tokenizer.rs` (5-Block Prefix-Hash KV-Cache Accounting)**:
   * Computes deterministic chained BLAKE3 prefix hashes for provider KV-cache accounting:
     * $\text{Hash}_{\text{BP1}} = \text{BLAKE3}(\text{"tantry:kv:bp1:v3"} \parallel \text{Block1StaticSystem} \parallel \text{Block2StaticTools})$.
     * $\text{Hash}_{\text{BP2}} = \text{BLAKE3}(\text{"tantry:kv:bp2:v3"} \parallel \text{Hash}_{\text{BP1}} \parallel \text{Block3SemiStaticSkillsAndRepoMap} \parallel \text{Block4SemiStaticMemory})$.
   * Records `tantry_kv_cache_hit_ratio` (`cached_tokens as f64 / input_tokens.max(1) as f64`).
2. **`src/router.rs` (12D Contextual Disjoint LinUCB + Projected Thompson Sampling Router)**:
   * **12D Context Feature Vector $\mathbf{x}_t \in \mathbb{R}^{12}$**:
     $$\mathbf{x}_t = \left[1.0,\; \min\left(\frac{\text{tokens}_{\text{ctx}}}{128000}, 1.0\right),\; \text{blast\_radius\_risk},\; \mathbb{I}(\text{has\_vfs\_conflict}),\; \min\left(\frac{\text{consec\_errors}}{3.0}, 1.0\right),\; \min\left(\frac{\text{cyclomatic}}{50.0}, 1.0\right),\; \min\left(\frac{\text{todos}}{10.0}, 1.0\right),\; \mathbb{I}(\text{read\_only\_loop}),\; \text{budget\_rem\_ratio},\; \min\left(\frac{\text{depth}}{25.0}, 1.0\right),\; \mathbb{I}(\text{structured\_schema}),\; \mathbb{I}(\text{is\_utility\_call})\right]^\top$$
   * **Deterministic Safety Guardrails (Clamping Valid Arm Set $\mathcal{A}_{\text{valid}}(\mathbf{x}_t)$)**:
     1. Explicit `tier_override == Some(tier)` $\implies \mathcal{A}_{\text{valid}} = \{\text{tier}\}$.
     2. Utility call from `SummarizationMiddleware` or `RubricMiddleware` (`is_utility_call == 1.0`) $\implies \mathcal{A}_{\text{valid}} = \{\text{CompactLite}\}$.
     3. Unresolved `VfsMergeConflict` (`has_vfs_conflict == 1.0`), `blast_radius_risk >= 0.75`, or `consec_errors >= 2` $\implies \mathcal{A}_{\text{valid}} = \{\text{FrontierDeep}\}$.
     4. Read-only discovery loop (`read_only_loop == 1.0`, $\text{tokens}_{\text{ctx}} < 16,000$, non-empty `todos`) $\implies \mathcal{A}_{\text{valid}} = \{\text{FastExecution}, \text{ReasoningPro}\}$.
   * **Pure-Rust $12 \times 12$ Gauss-Jordan Inversion & Hybrid Selection Score**:
     * Each arm $a \in \{\text{FrontierDeep}, \text{ReasoningPro}, \text{FastExecution}, \text{CompactLite}\}$ persists $\mathbf{A}_a \in \mathbb{R}^{12 \times 12}$ (initialized to $\lambda \mathbf{I}_{12}, \lambda = 1.0$) and $\mathbf{b}_a \in \mathbb{R}^{12}$ in `linucb_bandit_arms`.
     * Inverts $\mathbf{A}_a$ via pure-Rust $12 \times 12$ Gauss-Jordan elimination with partial pivoting (adding Tikhonov jitter $10^{-6} \mathbf{I}_{12}$ if any pivot $< 10^{-9}$), computes $\hat{\boldsymbol{\theta}}_a = \mathbf{A}_a^{-1} \mathbf{b}_a$ and uncertainty $\sigma_a(\mathbf{x}_t) = \sqrt{\max(\mathbf{x}_t^\top \mathbf{A}_a^{-1} \mathbf{x}_t, 0.0)}$, and selects:
       $$a^* = \arg\max_{a \in \mathcal{A}_{\text{valid}}(\mathbf{x}_t)} \left(\hat{\boldsymbol{\theta}}_a^\top \mathbf{x}_t + \left(\alpha_{\text{ucb}} + \alpha_{\text{ts}} \cdot z_a\right) \sigma_a(\mathbf{x}_t)\right)$$
       where $\alpha_{\text{ucb}} = 0.25$, $\alpha_{\text{ts}} = 0.05$ (or $0.0$ in deterministic evaluation mode), and $z_a \in [-2.0, 2.0]$ is a clamped standard normal sample.
   * **Online Update & `PendingBanditFeedbackSlot`**:
     * Stores `PendingBanditFeedbackSlot { selected_tier: ModelTier, context_x: [f64; 12], cost_micros: u64, latency_ms: u64 }` in `state.extensions` (`WIRE_KEY = "tantry.cognitive.bandit_feedback"`, `VISIBILITY = SlotVisibility::Private`, `CODEC_TAG = CodecTag::RkyvAligned`).
     * After tool execution and CST linting complete, computes composite reward $r_t \in [0.0, 1.0]$:
       $$r_t = 0.55 \cdot \mathbb{I}(\text{tools\_succeeded\_and\_lint\_clean}) + 0.25 \cdot \left(1.0 - \min\left(\frac{\text{cost\_micros}}{50000.0}, 1.0\right)\right) + 0.20 \cdot \left(1.0 - \min\left(\frac{\text{latency\_ms}}{15000.0}, 1.0\right)\right)$$
       Updates $\mathbf{A}_{a^*} \leftarrow \mathbf{A}_{a^*} + \mathbf{x}_t \mathbf{x}_t^\top$ and $\mathbf{b}_{a^*} \leftarrow \mathbf{b}_{a^*} + r_t \mathbf{x}_t$, and persists to `linucb_bandit_arms`.

### Crate `cognitive`: Phase 2 — SIMD Semantic Cache & Atomic Credit-Lease Budget Enforcer
1. **`src/semantic_cache.rs` (SIMD Semantic Cache & Mutation Bypass Invariant)**:
   * **Mutation Bypass Invariant**: Immediately skips cache lookup and returns `Ok(None)` if the latest message in `state.messages` contains a `ContentBlock::ToolResult` from any tool where `is_mutating_for_semantic_cache == true` (`write_file`, `edit_file`, `delete`, `execute`, `eval`, `browser`, `computer`, `task`).
   * Computes context partition key `BLAKE3(model_tier || sorted_tool_names_blake3 || block1_system_blake3)` and queries `MatryoshkaVectorStore` over the normalized embedding of the last 3 messages.
   * Implements bit-identical Int8/Int8 dot-product acceleration across `aarch64` NEON (`vdotq_s32`) and `x86_64` AVX2 (sign-extending `i8` to `i16` via `_mm256_cvtepi8_epi16` and accumulating via `_mm256_madd_epi16`) with scalar fallback.
   * Encrypts cached `Message` payloads in `semantic_cache.sqlite` using the canonical `crates/data` AEAD + `zstd` envelope.
2. **`src/billing.rs` (Reservation-Based Atomic Credit-Lease Enforcer & 90% Signed Webhook Gate)**:
   * **Pre-Flight Lease (`acquire_lease`)**: Computes worst-case estimated cost:
     $$\text{lease\_micros} = \left\lceil \frac{N_{\text{in\_est}} \cdot P_{\text{in}} + N_{\text{max\_out}} \cdot P_{\text{out}}}{10^6} \right\rceil$$
     Calls `TaskLedgerStore::try_reserve_budget(task_id, lease_micros)`. Returns `Err(CognitiveError::BudgetExhausted)` if `spent + reserved + lease > hard_budget_micros`; otherwise returns RAII `BudgetLeaseGuard`.
   * **Mid-Flight Lease Upgrade (`upgrade_lease`)**: When speculative cascade escalates from a draft tier (`CompactLite`/`FastExecution`) to a verifier tier (`ReasoningPro`/`FrontierDeep`), atomically reserves the delta $\Delta\text{lease} = \text{lease}_{\text{target}} - \text{lease}_{\text{draft}}$ before dispatching the target request.
   * **Post-Call Settlement & Signed 90% Webhook (`settle`)**:
     * Computes actual cost $\Delta\text{cost\_micros} = \left\lceil \frac{(N_{\text{in}} - N_{\text{cached}}) \cdot P_{\text{in}} + N_{\text{cached}} \cdot P_{\text{cached}} + N_{\text{out}} \cdot P_{\text{out}}}{10^6} \right\rceil$.
     * Calls `TaskLedgerStore::settle_budget`. If `Drop` runs before `settle()` (e.g., task cancellation or network error), rolls back `reserved_budget_micros -= lease_micros`.
     * When `should_fire_webhook == true`, constructs `BudgetWebhookPayload { task_id, thread_id, tenant_id, spiffe_id, spent_micros, hard_budget_micros, timestamp_ms }`, mints a workload `JwtSvid` and RFC 9449 `DPoP` proof (`htm = "POST"`, `htu = webhook_url`), sends a synchronous HTTP POST (`timeout = webhook_timeout_ms`) with headers `Authorization: DPoP <jwt_svid>` and `DPoP: <dpop_proof>`, marks `webhook_90_fired = 1`, and appends `BUDGET_90_WEBHOOK_FIRED` to `audit_log.sqlite`.

### Crate `cognitive`: Phase 3 — Speculative Cascade Verifier & MCP Sampling Bridge (`src/lib.rs`)
1. **`LlmProvider` Trait & Speculative Cascade**:
   * `LlmProvider`: `complete(&self, req: ModelRequest) -> Result<ModelResponse, CognitiveError>` and `stream_complete(&self, req: ModelRequest) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CognitiveError>> + Send>>, CognitiveError>`.
   * Inspects the first 64 tokens of streaming draft responses for malformed tool JSON or low log-probability confidence; if detected, cancels the draft stream, calls `guard.upgrade_lease(target_tier)`, and transparently restarts generation on `ReasoningPro` or `FrontierDeep`.
2. **MCP `sampling/createMessage` Guard (`execute_mcp_sampling_request`)**:
   * Reads `McpSamplingDepthSlot` from `state.extensions`. If `depth >= 2`, rejects immediately with `CognitiveError::McpSamplingRecursionLimitExceeded(depth)`. Otherwise increments `depth + 1`, acquires a `BudgetLeaseGuard` against the parent task's `task_ledger` row, executes the completion, and settles the lease.

---
