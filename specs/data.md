## 5. Crate 4: `crates/data` (Nonce-Misuse-Resistant AEAD Ledgers, RFC 6962 MMR Audit & RaBitQ Vector Store)

### Crate `data`: Phase 1 — Writer-First `DbHandle`, Canonical AAD Envelope & $O(1)$ Crypto-Shredding
1. **`src/error.rs` & `src/db.rs` (Writer-First SQLite WAL Pool)**:
   * `DataError`: `Sqlite(#[from] rusqlite::Error)`, `AeadError(String)`, `AadMismatch`, `ZstdError(String)`, `CryptoShredded(String)`, `CheckpointNotFound(String)`, `TamperedAuditEntry(u64)`, `MmrProofInvalid`, `Serialization(String)`.
   * **`DbHandle` Writer-First Initialization Invariant**:
     * Opens the single `Arc<Mutex<Connection>>` **writer connection first**.
     * Executes `PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;`.
     * Executes all `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` DDL statements for the database, followed by `PRAGMA wal_checkpoint(PASSIVE);`.
     * **Only after the writer DDL and WAL checkpoint complete** does `DbHandle` open the read-only connection pool (`OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX`) so readers never encounter uninitialized WAL shared-memory (`-shm`) errors.
2. **`src/crypto.rs` (`zstd` + `XChaCha20-Poly1305` / `AES-256-GCM-SIV` Envelope & `key_epochs` Sync)**:
   * **Canonical 32-Byte Structured AAD**:
     $$\text{AAD} = \text{BLAKE3}\left(\text{"tantry:aad:v3"} \parallel \text{table\_name} \parallel \text{primary\_key} \parallel \text{thread\_id} \parallel \text{key\_epoch}_{\text{BE32}}\right)$$
   * **Wire Format**: `[version: u8 = 0x03][cipher_id: u8 (0x01 = XChaCha20Poly1305, 0x02 = Aes256GcmSiv)][nonce: 24B (for 0x01) or 12B (for 0x02)][ciphertext_and_16B_tag]`.
     * Nonce generation for `XChaCha20-Poly1305` (24 bytes): `timestamp_ms_be64 || atomic_counter_be64 || os_csprng_8_bytes` (immunizing against VM snapshot restores).
     * Plaintext is compressed with `zstd::encode_all(plaintext, 3)` prior to encryption and decompressed via `zstd::decode_all` after authenticated decryption.
   * **Auto-Provisioning & Two-Phase `crypto_shred_thread(thread_id)`**:
     * On first write for `(thread_id, key_epoch)`, if no row exists in `key_epochs`, generates 32-byte CSPRNG `epoch_salt` and `thread_salt` and inserts them into `key_epochs`.
     * Before deriving a DEK for any read/write, queries `key_epochs` for `(row.thread_id, row.key_epoch)`. If `shredded != 0` or `thread_salt IS NULL`, immediately returns `Err(DataError::CryptoShredded(thread_id))`.
     * `crypto_shred_thread(thread_id)`: Inside a `BEGIN IMMEDIATE` transaction on `interaction_chain.sqlite`, first executes `UPDATE key_epochs SET thread_salt = zeroblob(32) WHERE thread_id = ?1` (overwriting page bytes in-place), then executes `UPDATE key_epochs SET thread_salt = NULL, shredded = 1 WHERE thread_id = ?1`, commits, runs `PRAGMA wal_checkpoint(TRUNCATE);`, and invokes `key_hierarchy.crypto_shred_thread(thread_id)`.

### Crate `data`: Phase 2 — `TaskLedgerStore` & Time-Travel `InteractionChainStore`
1. **Relational Schemas (`task_ledger.sqlite`, `interaction_chain.sqlite`, `audit_log.sqlite`)**:
   * All 8 tables and their exact columns, `CHECK` constraints, and indexes MUST match Section 6.2 of the Master Schema:
     * `task_ledger.sqlite`: `task_ledger`, `linucb_bandit_arms` (`arm_tier TEXT PRIMARY KEY`, `matrix_a_blob BLOB NOT NULL` [144 `f64` LE = 1152B], `vector_b_blob BLOB NOT NULL` [12 `f64` LE = 96B], `pull_count INTEGER NOT NULL DEFAULT 0`, `updated_at_ms INTEGER NOT NULL`).
     * `interaction_chain.sqlite`: `key_epochs`, `interaction_checkpoints` (`UNIQUE(thread_id, step_index)`), `archived_messages`.
     * `audit_log.sqlite`: `audit_log`, `audit_mmr_nodes`, `audit_signed_tree_heads`.
2. **`src/task_ledger.rs` (`TaskLedgerStore`)**:
   * Implements `create_task`, `get_task`, `update_task_status`, `try_reserve_budget(task_id, lease_micros)` (atomic `BEGIN IMMEDIATE` checking `spent_budget_micros + reserved_budget_micros + lease_micros <= hard_budget_micros`), `upgrade_reserved_budget(task_id, additional_micros)`, `settle_budget(task_id, lease_micros, actual_cost_micros, soft_warning_ratio)` (atomically decrements `reserved_budget_micros`, increments `spent_budget_micros`, and returns `should_fire_webhook = true` if `spent >= floor(soft_warning_ratio * hard_budget)` and `webhook_90_fired == 0`), `mark_webhook_90_fired(task_id)`, `load_linucb_arms()`, and `upsert_linucb_arm(...)`.
3. **`src/interaction_chain.rs` (`InteractionChainStore` & Time-Travel Hydration Invariants)**:
   * **Strict `INSERT INTO` Invariant**: `commit_checkpoint` MUST use plain `INSERT INTO interaction_checkpoints ...` (NEVER `INSERT OR REPLACE`), so any accidental `(thread_id, step_index)` collision surfaces immediately instead of silently overwriting Step 1 and orphaning `previous_checkpoint_id` pointers.
   * **Checkpoint Digest (`checkpoint_blake3`)**:
     $$\text{checkpoint\_blake3} = \text{BLAKE3}\left(\text{"tantry:cp:v3"} \parallel \text{prev\_cp\_id} \parallel \text{thread\_id} \parallel \text{step\_index}_{\text{BE64}} \parallel \text{msg\_delta\_aead} \parallel \text{file\_deltas\_aead} \parallel \text{ext\_slots\_aead}\right)$$
   * **Ancestor Walk & Cross-Thread Decryption (`reconstruct_state_at_checkpoint(target_checkpoint_id, registry)`)**:
     1. Walks backward from `target_checkpoint_id` to genesis via `previous_checkpoint_id`, pushing each raw row onto `chain: Vec<RawCheckpointRow>`.
     2. **Step-Index Capture Invariant**: Captures `let target_step_index = chain.first().map(|r| r.step_index).unwrap_or(0);` and `let target_thread_id = chain.first()...` **before** reversing `chain`.
     3. Reverses `chain` (`chain.reverse()`) so rows are ordered oldest-to-newest (genesis $\rightarrow$ target).
     4. Initializes `let mut state = TantryState::default();` and replays each `row` in `chain`:
        * **Cross-Thread Fork Decryption Rule**: Decrypts `row.message_delta_aead`, `row.file_deltas_aead`, and `row.extension_slots_aead` using **`&row.thread_id`** and **`row.key_epoch`** (from that SQLite row, NEVER a caller-passed `thread_id`), binding `row.checkpoint_id` and `row.thread_id` in the AAD.
        * Applies `MessageDelta::apply(&mut state.messages, msg_delta)` and `FileDelta::apply_batch(&mut state.files, &file_deltas)`.
        * Deserializes `row.todos_json`, `row.async_tasks_json`, and calls `state.extensions.hydrate_all(&raw_slots, registry)`.
     5. Explicitly assigns `state.step_index = target_step_index;`, `state.thread_id = target_thread_id;`, and `state.last_checkpoint_id = Some(target_checkpoint_id.to_string());` before returning `ReconstructedCheckpoint { state, step_index: target_step_index, vfs_root_blake3: state.files.root_hash(), checkpoint_blake3 }`.
   * Helper queries: `get_latest_checkpoint_for_thread(thread_id) -> Result<Option<(String, u64)>, DataError>`, `get_checkpoint_id_by_step(thread_id, step_index) -> Result<Option<String>, DataError>`, and `list_archived_messages(thread_id) -> Result<Vec<Message>, DataError>`.

### Crate `data`: Phase 3 — RFC 6962 `AuditMmr`, Two-Stage RaBitQ Vector Index & `DataStoreManager`
1. **`src/audit_mmr.rs` (Linear `blake3` Chain + Post-Order RFC 6962 MMR)**:
   * **Linear Entry Hash ($H_n$)**: For 1-based `seq_no` $n$ (with $H_0 = [0\text{u8}; 32]$):
     $$H_n = \text{BLAKE3}\left(H_{n-1} \parallel \text{seq\_no}_{\text{BE64}} \parallel \text{timestamp\_ms}_{\text{BE64}} \parallel \text{spiffe\_id} \parallel \text{thread\_id} \parallel \text{event\_kind} \parallel \text{payload\_json}\right)$$
   * **MMR Post-Order Node Indexing (`audit_mmr_nodes`)**:
     * Leaf hash for entry $n$: $M_{\text{leaf}} = \text{BLAKE3}(0\text{x00} \parallel H_n)$ at `height = 0`.
     * Whenever the top two peaks on the stack have equal height $h$, pops right peak $R$ and left peak $L$ and pushes parent node $P = \text{BLAKE3}(0\text{x01} \parallel L \parallel R)$ at `height = h + 1` with sequential 1-based `mmr_pos`.
     * **Bagging Peaks (`compute_mmr_root(tree_size)`)**: Folds peaks from right (smallest) to left (largest) via $\text{acc} = \text{BLAKE3}(0\text{x02} \parallel \text{peak}_{\text{left}} \parallel \text{acc})$.
   * **Proofs & Verification**:
     * `generate_inclusion_proof(seq_no)` & `verify_inclusion_proof(&proof, expected_mmr_root) -> bool` via `mountain_audit_path` in $O(\log N)$.
     * `generate_consistency_proof(old_size, new_size)` & `verify_consistency_proof(&proof, old_root, new_root) -> bool`.
     * `record_signed_tree_head(&self, iam: &dyn IdentityManager) -> Result<AuditSthSignature, DataError>` and `verify_all_chain_and_sths(&self, iam: &dyn IdentityManager) -> Result<(), u64>` (returns `Err(corrupted_seq_no)` on any linear chain, MMR node, or PQ STH mismatch).
2. **`src/vector_index.rs` (Two-Stage Matryoshka Binary/Int8 RaBitQ Vector Index)**:
   * **Stage 1 (1-Bit Binary Quantization Coarse Filter)**: Truncates normalized embedding $\mathbf{v} \in \mathbb{R}^D$ to Matryoshka prefix $d \in \{256, 512\}$, packs sign bits ($v_i \ge 0 \rightarrow 1$, else $0$) into `[u64; 8]`, and scans all entries using hardware `u64::count_ones()` (`POPCNT` on `x86_64`, `CNTP` on `aarch64` NEON) Hamming distance to select the top $K_1 = \min(4096, N)$ candidates in $< 0.4\text{ms}$.
   * **Stage 2 (Asymmetric Int8/Float32 RaBitQ Rescoring)**: Quantizes candidate vectors into symmetric `i8` values $q_i = \text{round}(127.0 \cdot v_i / \|\mathbf{v}\|_\infty)$ with scale factor $s = \|\mathbf{v}\|_\infty / 127.0$, and rescores the $K_1$ candidates against the full-precision query vector $\mathbf{u} \in \mathbb{R}^D$ with RaBitQ corrective norm scaling, returning top-$K$ results with cosine similarity $\ge \theta$.
3. **`src/lib.rs` (`DataStoreManager` Facade)**:
   * Bundles `task_ledger: Arc<TaskLedgerStore>`, `interaction_chain: Arc<InteractionChainStore>`, `audit_mmr: Arc<AuditMmrStore>`, and `vector_index: Arc<MatryoshkaVectorStore>`.
   * `verify_all_integrity(&self, iam: &dyn IdentityManager) -> Result<IntegrityReport, DataError>`: Verifies the entire `audit_log` linear chain, MMR nodes, PQ Signed Tree Heads, and every AEAD authentication tag across `interaction_checkpoints` and `archived_messages` (skipping rows whose `(thread_id, key_epoch)` is marked `shredded == 1`).

---
