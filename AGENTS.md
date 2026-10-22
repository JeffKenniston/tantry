# Autonomous Agent Ruleset: Rust Phase Implementation

You are executing tasks as an asynchronous development engineer within this repository. Follow this strict execution model to enforce iterative development and safe compilation.

## System Context & Repositories
* **Active Specification File:** Always refer directly to the `.md` spec file matching the targeted crate located under the `specs/` directory.
* **Test Specifications File:** The `specs/tests.md` file contains TDD tests for the project.
* **Scope Constraint:** Focus entirely on the structures required for the user-specified Phase. Do not eagerly implement logic, public APIs, or traits intended for subsequent phases

## Execution Workflow (The Plan Generation Stage)
When the user gives you a task to implement a specific Phase of a crate, your generated Plan MUST explicitly define the following internal loop sequence before you start editing code:

1. **Analysis & Baseline Identification:**
   * Scan `specs/` for the targeted crate and test specifications.
   * Map out all required data structures, traits, error variants, and tests needed for the specific Phase.

2. **Complete Implementation Execution:**
   * Write production-ready, idiomatic Rust code matching the phase/test requirements.
   * **Strict Constraint:** Never insert comments or placeholders such as `// TODO`, `unimplemented!()`, or `...`. Every path must be completely written and compile successfully.

3. **Autonomous Validation Loop (Self-Review):**
   * Execute `cargo check` and `cargo test` in your Cloud VM environment to verify syntactical safety, type compliance, and logic boundary rules.
   * Treat any compiler error, warning, or test failure as a strict "FAIL" status. You must immediately rewrite the offending module or section, re-run tests, and self-verify before finalizing.

## Rust Code Quality Standards
When optimizing or reviewing code changes during task planning and execution, strictly enforce:
* **Memory Safety:** Avoid unnecessary clones where borrowing is idiomatic; completely avoid unsafe Rust unless explicitly authorized by the specification sheet.
* **Idiomatic Patterns:** Enforce proper pattern matching, exhaustive enum checks, and idiomatic error bubbles utilizing the `Result<T, E>` and `Option<T>` patterns.
* **Documentation:** Provide proper Rust documentation comments (`///`) on all newly exposed public types, methods, or traits.
