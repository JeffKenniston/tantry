# Progress

## Completed Tasks

## Next Task
- **Step 1: Remove Spurious Lockfile & Configure `.cargo/config.toml` and Root `Cargo.toml`**
  * Delete the stray `crates/data/Cargo.lock` file so the workspace uses a single authoritative root `Cargo.lock`.
  * Create `.cargo/config.toml` at the repository root with `[profile.dev]` (`opt-level = 1`, `debug = "line-tables-only"`, `split-debuginfo = "unpacked"`), `[profile.release]` (`opt-level = 3`, `lto = "thin"`, `codegen-units = 4`, `strip = "symbols"`, `panic = "abort"`), and target rules for `aarch64-linux-android` (`linker = "clang"`, `rustflags = ["-C", "link-arg=-fuse-ld=lld", "-C", "link-arg=-Wl,--threads=4,--no-keep-memory", "-C", "target-cpu=generic", "-C", "target-feature=+neon,+crc,+crypto,+dotprod"]`), `x86_64-unknown-linux-gnu` (`+avx2,+fma,+aes,+sse4.2`), and `aarch64-unknown-linux-gnu` (`+neon,+crc,+crypto,+dotprod`).
  * Create the default root `config.toml` matching `specs/architecture.md` and `base::config::TantryConfig`.
  * Inspect root `Cargo.toml` to verify `edition = "2024"`, `resolver = "3"`, `rust-version = "1.85"`, `im` / `imbl-sized-chunks` and `aes-gcm` are absent, and `rpds = "1.1"`, `quinn = "0.11.12"`, `quinn-proto = ">=0.11.18"`, `wasmtime = "43.0.2"`, and `wasmparser = "0.224"` are pinned in `[workspace.dependencies]`.
