## 4. Crate 3: `crates/permissions` (Vectorized `GlobSet` DFA & 4D Join-Semilattice Policy Engine)

### Crate `permissions`: Phase 1 — `PermissionMode` Semilattice & Single-Pass `GlobSet` DFA
1. **`src/lattice.rs` (`PermissionMode` Bounded Join-Semilattice)**:
   * Enum `PermissionMode` (`#[repr(u8)]`): `Allow = 0`, `Interrupt = 1`, `Deny = 2`.
   * Partial Order ($\sqsubseteq$): $\text{Allow} \sqsubset \text{Interrupt} \sqsubset \text{Deny}$.
   * Least Upper Bound / Join ($\sqcup$): `pub fn join(self, other: Self) -> Self` returns `std::cmp::max(self, other)`. Satisfies idempotence ($a \sqcup a = a$), commutativity ($a \sqcup b = b \sqcup a$), associativity, and monotonicity ($a \sqsubseteq a \sqcup b$).
2. **`src/glob_dfa.rs` (Single-Pass Vectorized `GlobSet` Automaton)**:
   * `FsOperation` bitflags (`u8`): `READ = 0b0001`, `WRITE = 0b0010`, `DELETE = 0b0100`, `EXEC = 0b1000`, `ALL = 0b1111`.
   * `FsPolicyRule`: `glob_pattern: String`, `operations: FsOperation`, `mode: PermissionMode`, `required_spiffe_prefix: Option<String>`.
   * `CompiledFsAutomaton`: Compiles all `FsPolicyRule` patterns into a single `globset::GlobSet` DFA at construction time.
   * `evaluate(&self, svid: &SpiffeId, op: FsOperation, raw_path: &str) -> PermissionMode`:
     * Normalizes `raw_path` via `base::path::validate_and_normalize_path` (if path validation fails, immediately returns `PermissionMode::Deny`).
     * Runs `self.glob_set.matches(&normalized_path)` in a single $O(|p|)$ pass to obtain all matching rule indices.
     * Filters matching rules where `rule.operations.contains(op)` and `rule.required_spiffe_prefix.as_deref().map_or(true, |pfx| svid.uri().starts_with(pfx))`.
     * Joins ($\sqcup$) the `PermissionMode` of all matching applicable rules (or returns `self.default_mode` if no rule matched).

### Crate `permissions`: Phase 2 — 4-Dimensional Capability Evaluators
1. **`src/capabilities.rs` (`FsCapability`, `NetCapability`, `EnvCapability`, `McpCapability`)**:
   * **Dimension 1 (`FsCapability`)**: Wraps `CompiledFsAutomaton`.
   * **Dimension 2 (`NetCapability`)**:
     * Rules specify `domain_glob: String` (e.g., `"*.crates.io"`), `allowed_ports: Vec<(u16, u16)>`, `allowed_methods: Vec<String>`, `mode: PermissionMode`.
     * `evaluate_egress(&self, host: &str, port: u16, method: Option<&str>, tunnel_registry: Option<&ScopedTunnelRegistry>, now_ms: i64) -> PermissionMode`: If `tunnel_registry` reports `is_service_active(host, now_ms) == true`, returns `PermissionMode::Allow` unless an explicit `Deny` rule matches `host`; otherwise evaluates the compiled domain `GlobSet` and port/method constraints.
   * **Dimension 3 (`EnvCapability`)**:
     * Mandatory hard-coded secret deny-globs compiled into a dedicated `secret_deny_globset`: `["*KEY*", "*TOKEN*", "*SECRET*", "*PASSWORD*", "*CREDENTIAL*", "*PRIVATE*", "*BEARER*"]` (case-insensitive).
     * `scrub_host_env<I>(&self, host_vars: I) -> BTreeMap<String, String>`: Filters host environment variables, unconditionally dropping any key matching `secret_deny_globset` unless explicitly overridden by an exact-match `Allow` rule, and only passing through keys permitted by the policy's `allow_globs`.
   * **Dimension 4 (`McpCapability`)**:
     * Rules specify `server_tool_glob: String` (`"server_name:tool_name"`), `max_spend_micros_per_call: u64`, `mode: PermissionMode`.
     * `evaluate_mcp_call(&self, server_name: &str, tool_name: &str, estimated_spend_micros: u64) -> PermissionMode`: If `estimated_spend_micros > self.effective_max_spend_micros`, returns `PermissionMode::Deny`; otherwise evaluates `"{server_name}:{tool_name}"` against the compiled MCP `GlobSet`.

### Crate `permissions`: Phase 3 — `PermissionLattice` Subagent Attenuation & Zenoh Topic Guard
1. **`src/attenuation.rs` (`PermissionLattice` & Pointwise Join Attenuation Law)**:
   * `PermissionLattice`: Combines `fs: FsCapability`, `net: NetCapability`, `env: EnvCapability`, `mcp: McpCapability`, and `interrupt_on_tools: BTreeMap<String, PermissionMode>`.
   * `PermissionLattice::narrow_for_subagent(&self, child_requested: &PermissionLattice) -> PermissionLattice`:
     * Constructs a composite lattice where every evaluation query $x$ across any of the 4 dimensions or `interrupt_on_tools` computes the pointwise least upper bound:
       $$\text{Effective}(x) = \mathcal{P}_{\text{parent}}(x) \sqcup \mathcal{C}_{\text{child}}(x)$$
     * Sets `effective_max_spend_micros = min(self.mcp.max_spend_micros, child_requested.mcp.max_spend_micros)`.
     * **Mathematical Guarantee**: For all inputs $x$, $\text{Effective}(x) \sqsupseteq \mathcal{P}_{\text{parent}}(x)$. A child subagent can NEVER downgrade `Deny` to `Interrupt`/`Allow`, nor downgrade `Interrupt` to `Allow`.
2. **`src/zenoh_guard.rs` (`evaluate_zenoh_topic`)**:
   * `pub fn evaluate_zenoh_topic(svid: &SpiffeId, key_expr: &str, is_publish: bool) -> PermissionMode`:
     * Rejects any `key_expr` containing `..`, null bytes, or leading/trailing slashes.
     * For a root agent (`spiffe://{td}/agent/{a}/task/{tid}`), permits `tantry/{td}/**`.
     * For a subagent (`.../subagent/{s}/task/{child_tid}`), if `is_publish == true`, permits ONLY `tantry/{td}/subagents/{s}/tasks/{child_tid}/events` and `tantry/{td}/subagents/{s}/tasks/{child_tid}/state`; if `is_publish == false`, permits subscribing ONLY to `tantry/{td}/subagents/{s}/tasks/{child_tid}/cmd`. All other topics return `PermissionMode::Deny`.

---
