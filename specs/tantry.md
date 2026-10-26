## 13. Crate 12: `crates/tantry` (`TantryBuilder<HasBackend, HasIdentity>` & 10-Stage Agent Compiler)

### Crate `tantry`: Phase 1 — Typestate Builder, Compilation Guardrails & `CompiledTantryAgent`
1. **Compile-Time Typestate Markers (`src/builder.rs`)**:
   * `MissingBackend`, `BackendProvided(Arc<dyn VfsBackend>)`, `MissingIdentity`, `IdentityProvided(Arc<dyn IdentityManager>)`.
   * `TantryBuilder<B, I>` starts at `TantryBuilder<MissingBackend, MissingIdentity>::new(config: TantryConfig)`.
   * `.with_backend(backend)` transitions `B` $\rightarrow$ `BackendProvided`; `.with_identity(identity)` transitions `I` $\rightarrow$ `IdentityProvided`.
   * `.build(self) -> Result<CompiledTantryAgent, BuildError>` is ONLY implemented on `TantryBuilder<BackendProvided, IdentityProvided>`.
2. **10-Stage Deterministic Compilation Pipeline (`build()`)**:
   * **Stage 1 (Config & Platform Validation)**: Runs `TantryConfig::validate` and Termux `${PREFIX}` path rebasing.
   * **Stage 2 (Profile Resolution & Algebraic Merge)**: Resolves the active `HarnessProfile` via `ProfileRegistry::resolve` and applies any caller-supplied `HarnessProfileOverride`.
   * **Stage 3 (Mandatory Scaffolding Guard)**: If `"FilesystemMiddleware"` is present in `effective_profile.excluded_middleware`, immediately aborts with `Err(BuildError::RequiredScaffoldingExcluded("FilesystemMiddleware"))`.
   * **Stage 4 (Mandatory `read_file` Tool Guard)**: If `"read_file"` is present in `effective_profile.excluded_tools`, immediately aborts with `Err(BuildError::MissingMandatoryReadFileTool)`.
   * **Stage 5 (Capability-Driven Tool Pruning)**: Inspects `backend.capabilities()`:
     * If `!capabilities.supports_delete`, inserts `"delete"` into `effective_profile.excluded_tools`.
     * If `!capabilities.supports_execute`, inserts `"execute"` into `effective_profile.excluded_tools`.
   * **Stage 6 (17-Slot Onion Compilation)**: Compiles the 17 middleware slots in canonical order (`1..=17`), applying Zone 2 custom middleware insertions/replacements.
   * **Stage 7 (Lexicographical Tool Schema Compilation)**: Collects all active `ToolDefinition`s, filters out `effective_profile.excluded_tools`, applies `tool_description_overrides`, and sorts lexicographically by `tool.name` for Block 2 KV-cache stability.
   * **Stage 8 (`StateExtensionRegistry` Wiring)**: Registers hydrators for all built-in `StateSlot`s (`WorkloadIdentitySlot`, `SkeletonRepoMapSlot`, `PendingBanditFeedbackSlot`, `RoutingSignalsSlot`, `RubricIterationSlot`, `HitlBypassSlot`, `TurnDeltaBufferSlot`, `McpSamplingDepthSlot`) plus any caller-registered custom slots.
   * **Stage 9 (Subagent Factory Wiring)**: Recursively compiles the `general_purpose_subagent` profile and binds the subagent spawner closure into `RuntimeEngine`.
   * **Stage 10 (`CompiledTantryAgent` Assembly)**: Returns `CompiledTantryAgent` exposing `run_turn`, `stream_turn`, `resume`, `fork_thread_at_checkpoint`, `hydrate_thread_state`, and `verify_audit_integrity`.

---
