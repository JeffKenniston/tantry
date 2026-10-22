## 14. Crate 13: `crates/cli` (`tantry` Binary CLI & 60fps Responsive `ratatui` TUI)

### Crate `cli`: Phase 1 — `clap 4.5` Subcommand Parser & Daemon/Audit/Time-Travel Runners
1. **`src/args.rs` & `src/commands.rs` (`[[bin]] name = "tantry"`)**:
   * Global flags: `--config <PATH>` (default `"config.toml"`), `--log-format <pretty|json>`.
   * **Subcommand 1 (`tantry boot [--daemon]`)**: Parses & validates `config.toml`, runs `HostCapabilityProbe::detect()`, initializes `DualModeIdentityProvider`, initializes `DataStoreManager` (all 3 encrypted SQLite ledgers), starts `ZenohBusTransport` (`1.10.1`), `QuicMcpTransport` (`0.11.12`), and the TLS SNI Egress Proxy (`127.0.0.1:18443`), warms the Firecracker/Termux Zygote sandbox pool, and awaits `SIGINT`/`SIGTERM` for graceful shutdown.
   * **Subcommand 2 (`tantry run <PROMPT> [-m <MODEL>] [-t <THREAD_ID>] [--rubric <RUBRIC>]`)**: Compiles `CompiledTantryAgent` and streams live execution events (`ModelDelta`, `ToolCallStart`, `ToolCallEnd`, `TurnComplete`) with ANSI formatting to stdout.
   * **Subcommand 3 (`tantry repl [-w <WORKSPACE>] [-t <THREAD_ID>]`)**: Launches the interactive 60fps `ratatui` TUI.
   * **Subcommand 4 (`tantry resume --thread-id <ID> --decision <approve|reject|edit> --tool-use-id <TOOL_ID> [--payload <JSON_OR_TEXT>]`)**: Constructs `ApprovalDecision`, invokes `agent.resume(thread_id, vec![decision])`, and streams the resumed turn to completion.
   * **Subcommand 5 (`tantry branch --from-thread <ID> --step <N> [--new-thread <NEW_ID>] [--prompt <TEXT>]`)**: Resolves `checkpoint_id` at step `N` via `get_checkpoint_id_by_step`, constructs optional `MessageDelta::Append(vec![Message::user(prompt)])`, calls `fork_thread_at_checkpoint`, and prints/runs the new counterfactual branch timeline.
   * **Subcommand 6 (`tantry audit --verify-chain`)**: Invokes `DataStoreManager::verify_all_integrity(&iam)` to verify the entire `blake3` linear chain, RFC 6962 MMR peaks, hybrid Ed25519 + ML-DSA-65 Signed Tree Heads in `audit_log.sqlite`, and XChaCha20-Poly1305 AAD tags across `interaction_chain.sqlite`. Exits with status code `0` on full integrity or status code `1` printing the exact corrupted `seq_no` or `checkpoint_id`.

### Crate `cli`: Phase 2 — 60fps Responsive Desktop & Termux Mobile `ratatui` TUI (`src/tui.rs`)
1. **60fps Render Loop & Credit-Backpressure Integration**:
   * Runs a `16.6ms` (`60Hz`) `tokio::time::interval` render loop paired with `crossterm::event::EventStream`.
   * On every render frame that drains buffered `StreamEvent`s from the runtime receiver channel, dispatches a `CreditGrant { stream_id, additional_credits: drained_count }` back to the `CreditControlledPublisher`, ensuring the TUI never lags or drops lifecycle frames even during high-frequency token streaming.
2. **Adaptive Breakpoint Layout (`cols >= 80` vs `cols < 80`)**:
   * **Desktop Multi-Pane Split View (`terminal_width >= 80`)**: Renders a 2x2 Quadrant Grid:
     * Top-Left (60% width, 70% height): Live Chat, Reasoning Accordion & Streaming Tool Output.
     * Top-Right (40% width, 70% height): Live VFS Merkle Diff Tree, CST Diagnostics & Blast Radius Risk Gauge.
     * Bottom-Left (60% width, 30% height): Active `TodoList`, Subagent Execution DAG & Async Tasks.
     * Bottom-Right (40% width, 30% height): SVID TTL Countdown, LinUCB Selected `ModelTier`, KV-Cache Hit Ratio & Credit-Lease Budget Gauge.
   * **Termux Mobile Portrait Tabbed View (`terminal_width < 80`)**: Automatically switches to a full-screen 4-Tab Bar switched via keys `1`–`4` or `Tab`:
     * `Tab 1 [Chat & Stream]`, `Tab 2 [Subagent DAG]`, `Tab 3 [VFS Diff & AST]`, `Tab 4 [HITL & Budget]`.
   * **Interactive HITL Approval Modal**: Whenever `StreamEvent::Interrupted` arrives, overlays a centered modal displaying the pending tool name, arguments, and blast radius report with hotkeys `[A]pprove`, `[R]eject`, and `[E]dit JSON`.

---
