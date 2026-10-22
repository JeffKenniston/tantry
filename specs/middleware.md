## 12. Crate 11: `crates/middleware` (17-Slot Onion Compiler, 22 Built-In Tools & 5-Block KV-Cache Compiler)

### Crate `middleware`: Phase 1 — `AgentMiddleware` Trait, 17-Slot Compiler & Zone 1 Middlewares (Slots 1–10)
1. **`src/compiler.rs` (17-Slot Onion Pipeline Compiler)**:
   * Compiles the canonical 17-slot pipeline across 3 zones:
     * **Zone 1 (Slots 1–10)**: Base Scaffolding Middlewares.
     * **Zone 2 (Slot 11)**: Caller-supplied custom `Arc<dyn AgentMiddleware>`. If a caller middleware's `.name()` matches any built-in slot in Zone 1 or Zone 3, it **replaces that built-in slot in-place at its canonical slot number**; otherwise it executes in Slot 11 in registration order.
     * **Zone 3 (Slots 12–17)**: Profile, Routing, Memory, Rubric, HITL/Audit, and Prompt Caching Tail Middlewares.
   * Filtering: Removes any non-mandatory slot whose `.name()` is in `profile.excluded_middleware` (rejecting `"FilesystemMiddleware"` exclusion with an error).
2. **`src/slots_zone1.rs` (Canonical Zone 1 Middlewares: Slots 1–10)**:
   * **Slot 1 (`IdentityAndBudgetMiddleware`)**: Attests/rotates hybrid PQ `WorkloadSvid`, populates `WorkloadIdentitySlot`, acquires pre-flight `BudgetLeaseGuard`, and injects W3C `traceparent`.
   * **Slot 2 (`TodoListMiddleware`)**: Registers `write_todos` and `read_todos` tools; mutates/reads `state.todos`.
   * **Slot 3 (`FilesystemMiddleware` — MANDATORY)**: Registers `ls`, `read_file` (**MANDATORY**), `write_file`, `edit_file`, `delete`, `glob`, `grep`, and `execute`. Runs `base::tools_meta::maybe_offload_tool_output` on every tool output ($> 20,000$ chars or $> 500$ lines $\rightarrow$ `/offloaded_tool_results/{tool_use_id}.txt` + first 15 lines, last 15 lines, and top 10 prioritized diagnostic lines with line numbers).
   * **Slot 4 (`RepoIntelligenceMiddleware`)**: Registers `ast_blast_radius` and `repo_map` tools. Automatically invokes `RepoEngine::on_file_mutated` after `write_file`/`edit_file` to append $< 2\text{ms}$ CST syntax diagnostics, updates `SkeletonRepoMapSlot`, and writes `blast_radius_risk` + `cyclomatic_complexity` into `RoutingSignalsSlot`.
   * **Slot 5 (`InterpreterAndSandboxMiddleware`)**: Registers `eval` (WASI 0.3 component sandbox), `browser` (CDP), `computer` (GUI), and `ephemeral_tunnel` (mints short-lived `ScopedTunnelToken` via `IdentityManager::request_scoped_tunnel_token`).
   * **Slot 6 (`SkillsMiddleware`)**: Scans `/skills/**/SKILL.md` in `state.files`, verifies `.sigstore.json` bundles via `profiles::sigstore` when `verify_sigstore_bundles = true`, parses YAML frontmatter (`name`, `description`, `tags`), and stores only progressive-disclosure `SkillFrontmatter` in `state.skills_metadata` (full skill body is read on-demand via `read_file`).
   * **Slot 7 (`SubAgentMiddleware`)**: Registers synchronous `task` tool supporting single or parallel subagent fan-out in `SubagentMode::Isolated` or `SubagentMode::Fork`. Enforces subagent recursion depth $\le 3$ (via `SubagentDepthSlot` to prevent fork bombs), delegates execution to `RuntimeEngine::execute_subagents`, and reconciles child `VfsTree`s via the 4-stage Mergiraf CST merger.
   * **Slot 8 (`AsyncSubAgentMiddleware`)**: Registers `launch_async_task`, `check_async_task`, `update_async_task`, `cancel_async_task`, and `list_async_tasks` over `zenoh`, `quic-mcp`, or `http-ap`, maintaining `state.async_tasks`.
   * **Slot 9 (`SummarizationMiddleware`)**: Two-stage context compaction:
     1. **Stage A (Old Tool Input Truncation)**: Truncates `write_file`/`edit_file` input payloads $> 2,000$ chars in messages older than $K = 6$ turns.
     2. **Stage B (Atomic Boundary Compaction at $> 85\%$ Context Utilization)**: Computes candidate cut index `cut_idx` covering the oldest $60\%$ of messages. **ToolUse/ToolResult Atomic Boundary Rule**: While `cut_idx > 0` and (`messages[cut_idx]` contains `ContentBlock::ToolUse` OR `messages.get(cut_idx + 1)` has `role == Role::Tool` / `ContentBlock::ToolResult`), decrements `cut_idx -= 1` so a `ToolUse` is **NEVER** separated from its corresponding `ToolResult`. Summarizes `0..=cut_idx` via `ModelTier::CompactLite` into the 4-section Markdown schema (`## Completed Objectives`, `## Mutated Files & Symbols`, `## Active Constraints & Errors`, `## Next Immediate Step`), applies `MessageDelta::CompactRange`, and records the delta in `TurnDeltaBufferSlot`.
   * **Slot 10 (`PatchToolCallsMiddleware`)**: Scans `state.messages` before model invocation; for any `ContentBlock::ToolUse { id, .. }` lacking a matching `ContentBlock::ToolResult { tool_use_id == id }`, appends a synthetic `Message::tool_result(id, true, "Tool call was cancelled or interrupted before completion.", None)` and records `MessageDelta::Append` in `TurnDeltaBufferSlot`.

### Crate `middleware`: Phase 2 — Zone 3 Middlewares (Slots 12–17) & 5-Block KV-Cache Prompt Compiler
1. **`src/slots_zone3.rs` (Canonical Zone 3 Middlewares: Slots 12–17)**:
   * **Slot 12 (`CognitiveRouterMiddleware`)**:
     * Pre-call: Commits any pending reward from `PendingBanditFeedbackSlot` into `linucb_bandit_arms`, checks `SemanticCache` (honoring the Mutation Bypass Invariant), builds the 12D feature vector $\mathbf{x}_t$ from `RoutingSignalsSlot` and `TantryState`, selects `ModelTier` via `CognitiveRouter` (applying Safety Guardrails 1–4), and records the new `PendingBanditFeedbackSlot`.
     * Post-call: Settles `BudgetLeaseGuard` (triggering the synchronous 90% webhook gate if threshold crossed).
   * **Slot 13 (`ProfileFilterMiddleware`)**: Filters active tool definitions against `profile.excluded_tools`, applies `profile.tool_description_overrides`, and attaches `system_prompt_prefix`/`suffix`.
   * **Slot 14 (`MemoryMiddleware`)**: Loads `/memories/AGENTS.md` and `/AGENTS.md` from `state.files` into `state.memory_contents: BTreeMap<PosixPath, String>`, and exposes the `update_memory` tool.
   * **Slot 15 (`RubricMiddleware`)**: In `after_agent`, when `state.rubric_input` is `Some(rubric)`:
     * **Step 1 ($< 1\text{ms}$ Deterministic Pre-Check)**: Scans all modified files in `state.files` for `<<<<<<<` merge conflict markers or `tree-sitter` CST syntax errors (`has_error()`). If found, immediately sets `state.rubric_status = Some(RubricOutcome::Failed { feedback })`, appends a user feedback message, and returns `LoopDirective::ContinueTurn` without spending LLM tokens.
     * **Step 2 (`CompactLite` LLM Grader)**: Checks `RubricIterationSlot` (max iterations $= 3$). Invokes `ModelTier::CompactLite` to grade the assistant output against `rubric`. If satisfied, sets `RubricOutcome::Satisfied` and returns `LoopDirective::FinishTurn`; otherwise injects grader feedback and returns `LoopDirective::ContinueTurn` (or `RubricOutcome::MaxIterationsReached { iterations: 3 }` + `FinishTurn` at cap).
   * **Slot 16 (`HumanInTheLoopAndAuditMiddleware`)**: Evaluates every tool call against the 4D `PermissionLattice` (skipping `Interrupt` if `tool_use_id` is in `HitlBypassSlot`), routes MCP `elicitation/create` requests to HITL interrupt, and appends an immutable `blake3` + MMR entry to `audit_log.sqlite` for every tool invocation and security event.
   * **Slot 17 (`PromptCachingAndModalityMiddleware` & `src/prompt_cache.rs`)**:
     * Assembles the **5-Block Prefix-Stable Prompt Hierarchy**:
       1. **Block 1 (Static)**: Base System Prompt + Harness Instructions + Profile Prefix/Suffix.
       2. **Block 2 (Static — `CacheControl::Ephemeral` Breakpoint #1)**: Lexicographically sorted Tool Declarations JSON Schema (Draft 2020-12). *(Note: `RepoMap` MUST NOT be placed in Block 2 so Breakpoint #1 remains 100% static across file edits).*
       3. **Block 3 (Semi-Static)**: Lexicographically sorted `SKILL.md` Frontmatter Catalog (`state.skills_metadata`) + Skeletonized `RepoMap` (`SkeletonRepoMapSlot`).
       4. **Block 4 (Semi-Static — `CacheControl::Ephemeral` Breakpoint #2)**: Lexicographically sorted `AGENTS.md` Memory Contents (`state.memory_contents`).
       5. **Block 5 (Dynamic Per-Turn)**: Active `TodoList` (`state.todos`) + active `AsyncTaskHandle` summary (`state.async_tasks`).
     * Filters or transcodes `ContentBlock::Media` blocks unsupported by the resolved `HarnessProfile::supported_media_kinds`.

---
