# AGENTS.md — Tantry Autonomous Engineering Mandate

**Tantry** is a single-binary, capability-isolated, zero-trust, Rust-native **Agentic Operating System and Cognitive Harness**. It is engineered for standard Linux servers and unprivileged **Android Termux** environments.

## 1. Build, Check & Test Commands
Always verify your changes incrementally at the crate level before running workspace-wide checks. Zero warnings are strictly enforced:

### 1. Fast type and import check for a specific crate
RUSTFLAGS="-D warnings" cargo check -p <crate_name>

### 2. Run unit tests for a specific crate
RUSTFLAGS="-D warnings" cargo test -p <crate_name>

### 3. Full workspace verification gate (MUST pass cleanly)
RUSTFLAGS="-D warnings" cargo test --workspace

## 2. Planning & Guidance
When planning, or guidance is needed:
 * Every crate has a phased spec file located in the **specs/** directory. **Analyze** the relevant spec when needed.
 * Project layout & info, cross-crate dependency DAG, etc. is located in **specs/project.md**.

## 3. Non-Negotiable Coding Rules
 * Production-grade/ready code & implementations: No mocks, dummy's, "hacks", TODO comments, unimplemented, or simplifications are permitted in code. No skipping ANYTHING, all traits/structs/functions/logic/everything/etc. must be fully implemented!
 * Zero Panic Placeholders: Never commit panic-inducing macros or empty structures; all temporary scaffolding, todo!(), and unimplemented!() hooks must be fully implemented before staging.
 * Strict Error Propagation: Forbid the use of .unwrap() or .expect() on Option and Result types; every potential failure path must be explicitly mapped to a custom domain error type via idiomatic Result propagation.
 * Exhaustive Match Handling: Avoid wildcard match arms (_) when matching on local or internal domain enums; compile-time exhaustiveness checks must be strictly leveraged to catch unhandled states and edge cases.
 * No Mocked String-Matching or Fallbacks: Never use hardcoded strings like "Success" or mocked pattern-matching for dynamic tool execution. Dispatch tools dynamically through middleware hooks or backend interfaces.
 * No Large Multiline Regex Edits: Do not run multiline regex scripts to rewrite large blocks, as this corrupts syntax. Make targeted edits and verify immediately via cargo check.
 * Verify Workspace Exports: Before refactoring cross-crate calls, manually inspect the upstream crate's src/lib.rs to ensure the symbols actually exist and are public.
