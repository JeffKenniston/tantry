## 11. Crate 10: `crates/profiles` (Hierarchical `split_once(':')` Registry, Algebraic Merge & Sigstore Verifier)

### Crate `profiles`: Phase 1 — `HarnessProfile` Schema, First-Colon Registry & Algebraic Merge Laws
1. **`src/schema.rs` & `src/registry.rs`**:
   * **Strict First-Colon Key Split**: `parse_profile_key(key: &str) -> (&str, Option<&str>)` splits strictly on the **first** `':'` via `key.split_once(':')` (e.g., `"google_genai:gemini-3.1-pro:preview"` $\rightarrow$ provider `"google_genai"`, model `"gemini-3.1-pro:preview"`).
   * **Two-Level Inheritance**: Resolving `"provider:model"` clones the registered base `"provider"` profile and merges `"provider:model"` overrides on top via `HarnessProfile::apply_override`.
   * **Algebraic Additive Merge Laws (`apply_override`)**:
     * `excluded_tools: BTreeSet<String>` and `excluded_middleware: BTreeSet<String>`: **Set Union** ($A \cup B$).
     * `tool_description_overrides: BTreeMap<String, String>` and `init_kwargs: BTreeMap<String, serde_json::Value>`: **Key-Wise Map Merge** (override keys overwrite matching base keys; unmentioned base keys are preserved).
     * `extra_middleware: Vec<Arc<dyn AgentMiddleware>>`: **In-Place Replacement by `.name()`** (if an override middleware has the same `.name()` as an existing entry, it replaces that entry at its exact existing index; otherwise it appends at the tail).
     * `system_prompt_prefix` / `system_prompt_suffix` / `supported_media_kinds`: `Some(new_val)` replaces base value; `None` preserves base value.
     * `general_purpose_subagent: Option<Box<HarnessProfileOverride>>`: **Recursive Field-Wise Merge** applying these exact same laws recursively.

### Crate `profiles`: Phase 2 — 5-Block Token-Budget Allocator & Sigstore Bundle Verifier
1. **`src/budget_allocator.rs`**:
   * Computes proportional token caps across the 5 prompt blocks (`Block 1` static system, `Block 2` tool schemas, `Block 3` skills frontmatter + `RepoMap` capped at $2,500$ tokens, `Block 4` `AGENTS.md` memory capped at $4,000$ tokens, `Block 5` todos + async tasks) so total prompt overhead never exceeds $25\%$ of the model's context window.
2. **`src/sigstore.rs` (Fulcio + RFC 6962 Rekor + Hybrid PQ Sigstore Bundle Verifier)**:
   * Parses `.sigstore.json` / `.bundle` artifacts for `SKILL.md` skills and OCI profile bundles.
   * Verifies: (1) Artifact `BLAKE3` / `SHA-256` digest matches the bundle subject, (2) Fulcio leaf certificate chain validates against the trusted root and OIDC workload identity SAN, (3) Certificate validity timestamp falls within the Rekor transparency log entry `integratedTime` window, (4) RFC 6962 Rekor Merkle inclusion proof validates against the signed Rekor checkpoint, and (5) Optional ML-DSA-65 post-quantum signature validates when `require_pq_hybrid_signatures = true`.

---
