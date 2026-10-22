## 3. Crate 2: `crates/iam` (Post-Quantum Hybrid SVIDs, DPoP RFC 9449, Tunnel Grants & 3-Tier DEK Ratchet)

### Crate `iam`: Phase 1 — Error Taxonomy, `SpiffeId` Grammar & Pre-TBS PQ X.509v3 Binding
1. **`src/error.rs` & Memory Hygiene**:
   * All secret keys (`Ed25519` 32-byte seed, `ML-DSA-65` signing key, 256-bit `MasterKey`, `DekKey`) MUST wrap bytes in `zeroize::Zeroizing` or derive `ZeroizeOnDrop`.
   * `IamError`: `InvalidSpiffeId(String)`, `HierarchyViolation { parent: String, child: String }`, `TtlEscalation`, `CertificateGenerationError(String)`, `PqSignatureVerificationFailed`, `Ed25519VerificationFailed`, `DpopValidationFailed(String)`, `DpopReplayDetected(String)`, `MasterKeyUnavailable`, `KeyEpochShredded { thread_id: String, epoch: u32 }`, `TunnelGrantExpiredOrInvalid(String)`, `SpireSocketUnavailable(String)`.
2. **`src/spiffe.rs` (`SpiffeId` Parser & Attenuation Validator)**:
   * Root Agent URI: `spiffe://{trust_domain}/agent/{agent_name}/task/{task_id}`.
   * Subagent URI: `{parent_spiffe_id}/subagent/{subagent_name}/task/{child_task_id}`.
   * `SpiffeId::parse(uri: &str) -> Result<Self, IamError>`: Validates `spiffe://` scheme, RFC 3986 host `trust_domain`, non-empty path segments, no `.` or `..` segments.
   * `SpiffeId::derive_subagent(&self, subagent_name: &str, child_task_id: &str) -> Result<Self, IamError>`: Appends `/subagent/{subagent_name}/task/{child_task_id}` and verifies `child.uri().starts_with(&format!("{}/subagent/", self.uri()))`.
3. **`src/pq_ext.rs` (FIPS 204 ML-DSA-65 Pre-TBSCertificate X.509v3 Extension)**:
   * Custom X.509v3 OID: `1.3.6.1.4.1.99999.1.204` (`critical = false`).
   * **Pre-TBSCertificate Transcript (`compute_pre_tbs_pq_digest`)**: Computes 32-byte `BLAKE3` digest over:
     $$\text{BLAKE3}\left(\text{"tantry:x509-pq-tbs:v3"} \parallel \text{serial\_be} \parallel \text{issuer\_dn} \parallel \text{subject\_san\_uri} \parallel \text{not\_before\_s\_be64} \parallel \text{not\_after\_s\_be64} \parallel \text{is\_ca\_u8} \parallel \text{ed25519\_pk}_{32} \parallel \text{mldsa65\_pk}_{1952}\right)$$
   * Signs the 32-byte digest with the issuer's **ML-DSA-65** signing key (`3,309`-byte signature), encodes `PqExtensionPayload { subject_mldsa65_pk: Vec<u8> (1952B), issuer_mldsa65_sig: Vec<u8> (3309B), pre_tbs_blake3: [u8; 32] }` via `rmp_serde`, attaches it as custom extension OID `1.3.6.1.4.1.99999.1.204` in `rcgen::CertificateParams`, and signs the outer X.509v3 certificate with **Ed25519** (ensuring 100% compatibility with standard `rustls 0.23` TLS 1.3 mTLS).

### Crate `iam`: Phase 2 — Hybrid `JwtSvid`, RFC 9449 `DPoP`, `ScopedTunnelRegistry` & 3-Tier `KeyHierarchy`
1. **`src/svid.rs` (`WorkloadSvid` & Hybrid PQ `JwtSvid` Transcript)**:
   * `WorkloadSvid`: `spiffe_id: SpiffeId`, `cert_der_chain: Vec<Vec<u8>>`, `ed25519_pkcs8_der: Zeroizing<Vec<u8>>`, `ed25519_public_key: [u8; 32]`, `mldsa65_signing_key_bytes: Zeroizing<Vec<u8>>`, `mldsa65_verifying_key_bytes: Vec<u8>`, `issued_at: DateTime<Utc>`, `expires_at: DateTime<Utc>`.
   * `JwtSvidClaims`: `iss: String`, `sub: String` (`spiffe_id`), `aud: Vec<String>`, `exp: i64`, `iat: i64`, `jti: String` (UUIDv7), `pq_pk_b64: String`.
   * **Hybrid PQ JWS Encoding (`mint_hybrid_jwt_svid` & `verify_hybrid_jwt_svid`)**:
     * Computes `kid = hex(BLAKE3(ed25519_pk || mldsa65_pk)[0..16])`.
     * Base64url-encodes `JwtSvidClaims` into `claims_b64`.
     * Computes PQ signing transcript: `pq_digest = BLAKE3("tantry:jwt-svid:pq:v3:" || kid || "." || claims_b64)` and signs `pq_digest` with **ML-DSA-65** (`3,309` bytes $\rightarrow$ base64url `pq_sig_b64`).
     * Constructs JWS Protected Header `{"alg":"EdDSA","typ":"JWT","kid":kid,"pq_alg":"ML-DSA-65","pq_sig":pq_sig_b64}` $\rightarrow$ base64url `header_b64`.
     * Signs ASCII `"${header_b64}.${claims_b64}"` with **Ed25519** (`64` bytes $\rightarrow$ base64url `ed_sig_b64`) and outputs `"${header_b64}.${claims_b64}.${ed_sig_b64}"`.
     * Verification checks `exp > now`, audience inclusion, Ed25519 outer signature, and ML-DSA-65 `pq_sig` over `pq_digest` when `require_pq_hybrid_signatures = true`.
2. **`src/dpop.rs` (RFC 9449 Sender-Constrained OAuth 2.1 DPoP Engine)**:
   * `mint_dpop_proof(svid: &WorkloadSvid, htm: &str, htu: &str, access_token: Option<&str>) -> Result<String, IamError>`:
     * Strips query `?` and fragment `#` from `htu`.
     * Protected header: `{"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":base64url(ed25519_pk)}}`.
     * Payload: `{"jti":Uuid::now_v7().to_string(),"htm":htm.to_uppercase(),"htu":normalized_htu,"iat":Utc::now().timestamp(),"ath":access_token.map(|t| base64url(SHA256(t)))}`.
     * Signs with workload's Ed25519 key.
   * `verify_dpop_proof`: Validates header `typ == "dpop+jwt"`, reconstructs Ed25519 public key from `jwk`, verifies signature, checks `|now - iat| <= 60`, matches `htm`, `htu`, and `ath`, and records `jti` in a bounded LRU replay cache (`DashMap<String, i64>`).
3. **`src/tunnel_grant.rs` (`ScopedTunnelToken` & Lock-Free `ScopedTunnelRegistry`)**:
   * Used by WASI 0.3 `tunnel::request-scoped-token`, Slot 5 `ephemeral_tunnel` tool, and the TLS SNI Egress Proxy (`127.0.0.1:18443`).
   * `ScopedTunnelGrant`: `grant_id: String` (`jti`), `spiffe_id: SpiffeId`, `service_name: String` (normalized lowercase hostname, stripping `:port`), `expires_at_ms: i64`, `token: String`.
   * `ScopedTunnelRegistry`: Holds `by_id: DashMap<String, ScopedTunnelGrant>` and `by_service: DashMap<String, Vec<String>>`.
     * `normalize_host(raw: &str) -> String`: Trims scheme, path, and `:port` (so `"https://api.stripe.com:443"` and `"api.stripe.com:443"` both normalize to `"api.stripe.com"`).
     * `issue_grant`: Clamps `ttl_secs` to $[1, 3600]$, mints a hybrid `JwtSvid` with `aud = [format!("tunnel://{normalized_service}")]`, inserts into both maps, and returns `ScopedTunnelGrant`.
     * `verify_token(&self, token: &str, verifier: &dyn IdentityManager) -> Result<ScopedTunnelGrant, IamError>`: Verifies JWT signature, looks up `jti` in `by_id`, lazily evicts if `now_ms >= expires_at_ms`, and returns the active grant.
     * `is_service_active(&self, host_or_authority: &str, now_ms: i64) -> bool`: Normalizes `host_or_authority`, prunes expired `grant_id`s from `by_service`, and returns `true` if $\ge 1$ non-expired grant exists.
4. **`src/key_hierarchy.rs` (3-Tier Epoch-Ratcheted DEK Hierarchy & $O(1)$ Crypto-Shredding)**:
   * Domain separation constant: `pub const HKDF_DEK_DOMAIN_INFO: &[u8] = b"tantry-sqlite-aead-dek-v3";`
   * 3-Tier Derivation Chain:
     $$\text{DEK}_{\text{epoch}} = \text{HKDF-SHA256}\left(\text{ikm}=\text{KEK}_{\text{root}},\; \text{salt}=\text{epoch\_salt}_{32},\; \text{info}=\text{"tantry-sqlite-aead-dek-v3:epoch:"} \parallel \text{epoch\_id}_{\text{BE32}}\right)$$
     $$\text{DEK}_{\text{thread}} = \text{HKDF-SHA256}\left(\text{ikm}=\text{DEK}_{\text{epoch}},\; \text{salt}=\text{thread\_salt}_{32},\; \text{info}=\text{"tantry-sqlite-aead-dek-v3:thread:"} \parallel \text{thread\_id}\right)$$
   * `KeyHierarchy::derive_dek_from_salts(&self, epoch_id: u32, epoch_salt: &[u8; 32], thread_id: &str, thread_salt: &[u8; 32]) -> Zeroizing<[u8; 32]>`: Pure deterministic derivation used by `crates/data` during cross-thread time-travel hydration.
   * `KeyHierarchy::crypto_shred_thread(&self, thread_id: &str)`: Zeroizes and removes all cached `(thread_id, epoch_id)` entries in memory and marks the thread as shredded so subsequent derivation attempts return `Err(IamError::KeyEpochShredded)`.

### Crate `iam`: Phase 3 — 3-Tier Master Key Cascade, Audit STH Signing & Dual-Mode Providers
1. **`src/ca.rs` (3-Tier Master Key Cascade & `SovereignCaIdentityManager`)**:
   * **Master Key Acquisition Cascade (`acquire_or_init_master_key(data_dir)`)**:
     1. Inspects `std::env::var("TANTRY_MASTER_KEY")` (accepts 64-char hex or base64 32-byte key).
     2. Queries OS Keyring / Android Keystore bridge file `${data_dir}/.keystore_master.sealed`.
     3. Generates 32-byte CSPRNG seed and persists to `${data_dir}/.master_key.seed` with `0600` (`S_IRUSR | S_IWUSR`) permissions.
   * Seals/unseals the Root CA keypair (`Ed25519` + `ML-DSA-65`) at `${data_dir}/sovereign_ca.sealed` using `XChaCha20-Poly1305` with AAD `b"tantry:sovereign-ca:v3"`.
2. **Audit MMR Signed Tree Head Transcript (`AuditSthSignature`)**:
   * Struct `AuditSthSignature`: `tree_size: u64`, `timestamp_ms: i64`, `mmr_root_blake3: [u8; 32]`, `ed25519_sig: Vec<u8>` (64B), `mldsa65_sig: Vec<u8>` (3309B).
   * Deterministic STH Transcript:
     $$\text{digest}_{\text{STH}} = \text{BLAKE3}\left(\text{"tantry:audit:sth:v3"} \parallel \text{tree\_size}_{\text{BE64}} \parallel \text{timestamp\_ms}_{\text{BE64}} \parallel \text{mmr\_root\_blake3}_{32}\right)$$
   * `sign_audit_sth` signs $\text{digest}_{\text{STH}}$ with both the active workload/CA `Ed25519` key and `ML-DSA-65` key; `verify_audit_sth` verifies both signatures against the trust bundle.
3. **`src/spire.rs` & `src/lib.rs` (`IdentityManager` Trait, `SpireSocketIdentityManager`, `DualModeIdentityProvider` & `WorkloadIdentitySlot`)**:
   * `IdentityManager` trait methods: `current_svid()`, `mint_subagent_svid(parent_svid, subagent_name, child_task_id, requested_ttl)` (clamping `expires_at <= min(parent.expires_at, now + requested_ttl)`), `mint_jwt_svid(audience, ttl_secs)`, `verify_jwt_svid(token, expected_audience)`, `mint_dpop_proof(htm, htu, access_token)`, `verify_dpop_proof(proof, htm, htu, access_token)`, `request_scoped_tunnel_token(service_name, ttl_secs)`, `verify_scoped_tunnel_token(token)`, `is_service_tunnel_active(host_or_authority)`, `sign_audit_sth(tree_size, timestamp_ms, mmr_root_blake3)`, `verify_audit_sth(sth)`, and `key_hierarchy()`.
   * `SpireSocketIdentityManager`: Connects to `spire_socket_path` via `tokio::net::UnixStream`, rotates SVIDs at $80\%$ of TTL via background `tokio::sync::watch`, maintains a bounded ring buffer (`VecDeque`, max 16) of historical public key pairs across rotations so tokens/STHs signed prior to rotation still verify, and pairs SPIRE X.509/JWT credentials with a locally generated ephemeral ML-DSA-65 overlay keypair when SPIRE only provides classical keys.
   * `DualModeIdentityProvider`: Attempts `SpireSocketIdentityManager::connect` with a `500ms` timeout; if unavailable and `enable_embedded_sovereign_ca_fallback = true`, transparently initializes `SovereignCaIdentityManager`. Shares a single `Arc<ScopedTunnelRegistry>` and `Arc<KeyHierarchy>` across modes.
   * `WorkloadIdentitySlot`: Implements `base::typemap::StateSlot` (`WIRE_KEY = "tantry.iam.workload_identity"`, `VISIBILITY = SlotVisibility::Shared`, `CODEC_TAG = CodecTag::MessagePackNamed`) storing `(spiffe_id_uri, trust_domain, expires_at_ms, traceparent)`.

---
