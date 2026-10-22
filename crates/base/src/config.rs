use crate::error::{BaseError, ConfigValidationError};
use crate::path::PosixPath;
use crate::platform::{interpolate_env_vars, RuntimePlatform};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TantryConfig {
    pub system: SystemConfig,
    pub cognitive: CognitiveConfig,
    pub billing: BillingConfig,
    pub sandboxes: SandboxesConfig,
    pub transport: TransportConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemConfig {
    pub trust_domain: String,
    pub spire_socket_path: PosixPath,
    pub enable_embedded_sovereign_ca_fallback: bool,
    pub require_pq_hybrid_signatures: bool,
    pub data_dir: PosixPath,
    pub cache_dir: PosixPath,
    pub verify_sigstore_bundles: bool,
    pub strict_posix_paths: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CognitiveConfig {
    pub default_provider: String,
    pub semantic_cache_similarity_threshold: f32,
    pub semantic_cache_max_entries: usize,
    #[serde(alias = "enable_ucb1_bandit_routing")]
    pub enable_linucb_bandit_routing: bool,
    pub tiers: ModelTiersConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelTiersConfig {
    pub frontier_deep: String,
    pub reasoning_pro: String,
    pub fast_execution: String,
    pub compact_lite: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingConfig {
    pub webhook_url: String,
    pub soft_warning_ratio: f64,
    pub hard_stop_ratio: f64,
    pub webhook_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxesConfig {
    pub preferred_isolation_mode: String,
    pub max_workers: usize,
    pub wasm: WasmSandboxConfig,
    pub firecracker: FirecrackerSandboxConfig,
    pub termux_proot: TermuxProotSandboxConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WasmSandboxConfig {
    pub max_memory_bytes: usize,
    pub fuel_budget: u64,
    pub epoch_tick_ms: u64,
    pub wall_clock_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FirecrackerSandboxConfig {
    pub jailer_binary: PosixPath,
    pub firecracker_binary: PosixPath,
    pub kernel_image: PosixPath,
    pub warm_snapshot_pool_size: usize,
    pub restore_latency_target_ms: u64,
    pub egress_proxy_listen_addr: String,
    pub allowlisted_mirrors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TermuxProotSandboxConfig {
    pub proot_binary: PosixPath,
    pub rootfs_dir: PosixPath,
    pub uds_control_socket_dir: PosixPath,
    pub enable_seccomp_bpf: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransportConfig {
    pub zenoh_listen_endpoints: Vec<String>,
    pub quic_mcp_listen_addr: String,
    pub quic_handshake_fallback_timeout_ms: u64,
    pub mcp_protocol_version: String,
}

impl TantryConfig {
    pub fn parse_and_validate<F>(
        toml_str: &str,
        env_lookup: F,
        is_android_target: bool,
    ) -> Result<Self, BaseError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let interpolated = interpolate_env_vars(toml_str, &env_lookup);
        let mut config: Self = toml::from_str(&interpolated).map_err(|e| {
            BaseError::Config(ConfigValidationError::InvalidTrustDomain(format!(
                "TOML parsing failed: {}",
                e
            )))
        })?;

        let platform = RuntimePlatform::detect_from_env(&env_lookup, is_android_target);
        config.validate(&platform)?;

        Ok(config)
    }

    pub fn validate(&mut self, platform: &RuntimePlatform) -> Result<(), BaseError> {
        if self.system.trust_domain.is_empty() || self.system.trust_domain.contains('/') || self.system.trust_domain.contains(char::is_whitespace) {
            return Err(ConfigValidationError::InvalidTrustDomain(
                self.system.trust_domain.clone(),
            )
            .into());
        }

        self.system.spire_socket_path = platform.rebase_path(&self.system.spire_socket_path, self.system.strict_posix_paths)?;
        self.system.data_dir = platform.rebase_path(&self.system.data_dir, self.system.strict_posix_paths)?;
        self.system.cache_dir = platform.rebase_path(&self.system.cache_dir, self.system.strict_posix_paths)?;

        if self.cognitive.default_provider.is_empty() {
            return Err(ConfigValidationError::InvalidProvider(self.cognitive.default_provider.clone()).into());
        }

        if self.cognitive.semantic_cache_similarity_threshold < 0.50 || self.cognitive.semantic_cache_similarity_threshold > 1.00 {
            return Err(ConfigValidationError::InvalidSimilarityThreshold(
                self.cognitive.semantic_cache_similarity_threshold,
            )
            .into());
        }

        if self.cognitive.semantic_cache_max_entries == 0 {
            return Err(ConfigValidationError::InvalidSemanticCacheEntries(self.cognitive.semantic_cache_max_entries).into());
        }

        if !self.cognitive.tiers.frontier_deep.contains(':') {
            return Err(ConfigValidationError::InvalidModelTierFormat(self.cognitive.tiers.frontier_deep.clone()).into());
        }
        if !self.cognitive.tiers.reasoning_pro.contains(':') {
            return Err(ConfigValidationError::InvalidModelTierFormat(self.cognitive.tiers.reasoning_pro.clone()).into());
        }
        if !self.cognitive.tiers.fast_execution.contains(':') {
            return Err(ConfigValidationError::InvalidModelTierFormat(self.cognitive.tiers.fast_execution.clone()).into());
        }
        if !self.cognitive.tiers.compact_lite.contains(':') {
            return Err(ConfigValidationError::InvalidModelTierFormat(self.cognitive.tiers.compact_lite.clone()).into());
        }

        if !(self.billing.webhook_url.starts_with("http://") || self.billing.webhook_url.starts_with("https://")) {
            return Err(ConfigValidationError::InvalidUrl(self.billing.webhook_url.clone()).into());
        }

        if self.billing.soft_warning_ratio <= 0.0 || self.billing.soft_warning_ratio >= self.billing.hard_stop_ratio || self.billing.hard_stop_ratio > 1.0 {
            return Err(ConfigValidationError::InvalidBudgetRatios {
                soft: self.billing.soft_warning_ratio,
                hard: self.billing.hard_stop_ratio,
            }
            .into());
        }

        if self.billing.webhook_timeout_ms < 100 || self.billing.webhook_timeout_ms > 30000 {
            return Err(ConfigValidationError::InvalidWebhookTimeout(self.billing.webhook_timeout_ms).into());
        }

        match self.sandboxes.preferred_isolation_mode.as_str() {
            "auto" | "firecracker" | "termux_proot" | "wasm_only" => {},
            _ => return Err(ConfigValidationError::InvalidSandboxMode(self.sandboxes.preferred_isolation_mode.clone()).into())
        }

        if self.sandboxes.max_workers == 0 {
            return Err(ConfigValidationError::InvalidWorkerCount(self.sandboxes.max_workers).into());
        }

        self.sandboxes.max_workers = platform.effective_max_workers(self.sandboxes.max_workers);

        if self.sandboxes.wasm.max_memory_bytes < 16_777_216 || !num::Integer::is_multiple_of(&self.sandboxes.wasm.max_memory_bytes, &65536) {
            return Err(ConfigValidationError::InvalidWasmMemoryBytes(
                self.sandboxes.wasm.max_memory_bytes,
            )
            .into());
        }

        if self.sandboxes.wasm.fuel_budget == 0 {
            return Err(ConfigValidationError::InvalidWasmBudget(self.sandboxes.wasm.fuel_budget).into());
        }
        if self.sandboxes.wasm.epoch_tick_ms < 1 || self.sandboxes.wasm.epoch_tick_ms > 1000 {
            return Err(ConfigValidationError::InvalidEpochTick(self.sandboxes.wasm.epoch_tick_ms).into());
        }
        if self.sandboxes.wasm.wall_clock_timeout_ms < self.sandboxes.wasm.epoch_tick_ms {
            return Err(ConfigValidationError::InvalidWallClockTimeout(self.sandboxes.wasm.wall_clock_timeout_ms).into());
        }

        self.sandboxes.firecracker.jailer_binary = platform.rebase_path(&self.sandboxes.firecracker.jailer_binary, self.system.strict_posix_paths)?;
        self.sandboxes.firecracker.firecracker_binary = platform.rebase_path(&self.sandboxes.firecracker.firecracker_binary, self.system.strict_posix_paths)?;
        self.sandboxes.firecracker.kernel_image = platform.rebase_path(&self.sandboxes.firecracker.kernel_image, self.system.strict_posix_paths)?;

        if self.sandboxes.firecracker.egress_proxy_listen_addr.parse::<std::net::SocketAddr>().is_err() {
            return Err(ConfigValidationError::InvalidSocketAddr(self.sandboxes.firecracker.egress_proxy_listen_addr.clone()).into());
        }

        self.sandboxes.termux_proot.proot_binary = platform.rebase_path(&self.sandboxes.termux_proot.proot_binary, self.system.strict_posix_paths)?;
        self.sandboxes.termux_proot.rootfs_dir = platform.rebase_path(&self.sandboxes.termux_proot.rootfs_dir, self.system.strict_posix_paths)?;
        self.sandboxes.termux_proot.uds_control_socket_dir = platform.rebase_path(&self.sandboxes.termux_proot.uds_control_socket_dir, self.system.strict_posix_paths)?;

        if self.transport.zenoh_listen_endpoints.is_empty() {
             return Err(ConfigValidationError::InvalidEndpoints.into());
        }
        if self.transport.quic_mcp_listen_addr.parse::<std::net::SocketAddr>().is_err() {
            return Err(ConfigValidationError::InvalidSocketAddr(self.transport.quic_mcp_listen_addr.clone()).into());
        }
        if self.transport.quic_handshake_fallback_timeout_ms < 50 || self.transport.quic_handshake_fallback_timeout_ms > 5000 {
            return Err(ConfigValidationError::InvalidQuicTimeout(self.transport.quic_handshake_fallback_timeout_ms).into());
        }
        if self.transport.mcp_protocol_version != "2026-07-28" {
            return Err(ConfigValidationError::InvalidMcpProtocolVersion(
                self.transport.mcp_protocol_version.clone(),
            )
            .into());
        }

        Ok(())
    }
}
