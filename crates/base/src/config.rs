use std::net::SocketAddr;
use url::Url;
use serde::{Serialize, Deserialize};

use crate::error::{BaseError, ConfigValidationError};
use crate::platform::{RuntimePlatform, interpolate_env_vars};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    #[serde(default = "default_trust_domain")]
    pub trust_domain: String,
    #[serde(default = "default_spire_socket_path")]
    pub spire_socket_path: String,
    #[serde(default = "default_true")]
    pub enable_embedded_sovereign_ca_fallback: bool,
    #[serde(default = "default_true")]
    pub require_pq_hybrid_signatures: bool,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_cache_dir")]
    pub cache_dir: String,
    #[serde(default = "default_true")]
    pub verify_sigstore_bundles: bool,
    #[serde(default = "default_false")]
    pub strict_posix_paths: bool,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            trust_domain: default_trust_domain(),
            spire_socket_path: default_spire_socket_path(),
            enable_embedded_sovereign_ca_fallback: default_true(),
            require_pq_hybrid_signatures: default_true(),
            data_dir: default_data_dir(),
            cache_dir: default_cache_dir(),
            verify_sigstore_bundles: default_true(),
            strict_posix_paths: default_false(),
        }
    }
}

fn default_trust_domain() -> String { "tantry.internal".to_string() }
fn default_spire_socket_path() -> String { "${PREFIX:-}/run/spire/sockets/agent.sock".to_string() }
fn default_true() -> bool { true }
fn default_false() -> bool { false }
fn default_data_dir() -> String { "${PREFIX:-}/var/lib/tantry/data".to_string() }
fn default_cache_dir() -> String { "${PREFIX:-}/var/lib/tantry/cache".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelTiersConfig {
    #[serde(default = "default_frontier_deep")]
    pub frontier_deep: String,
    #[serde(default = "default_reasoning_pro")]
    pub reasoning_pro: String,
    #[serde(default = "default_fast_execution")]
    pub fast_execution: String,
    #[serde(default = "default_compact_lite")]
    pub compact_lite: String,
}

impl Default for ModelTiersConfig {
    fn default() -> Self {
        Self {
            frontier_deep: default_frontier_deep(),
            reasoning_pro: default_reasoning_pro(),
            fast_execution: default_fast_execution(),
            compact_lite: default_compact_lite(),
        }
    }
}

fn default_frontier_deep() -> String { "google_genai:gemini-4-argon".to_string() }
fn default_reasoning_pro() -> String { "google_genai:gemini-3.1-pro".to_string() }
fn default_fast_execution() -> String { "google_genai:gemini-3.8-flash".to_string() }
fn default_compact_lite() -> String { "google_genai:gemini-3.5-flash-lite".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveConfig {
    #[serde(default = "default_provider")]
    pub default_provider: String,
    #[serde(default = "default_similarity_threshold")]
    pub semantic_cache_similarity_threshold: f32,
    #[serde(default = "default_max_entries")]
    pub semantic_cache_max_entries: usize,
    #[serde(alias = "enable_ucb1_bandit_routing")]
    #[serde(default = "default_true")]
    pub enable_linucb_bandit_routing: bool,
    #[serde(default)]
    pub tiers: ModelTiersConfig,
}

impl Default for CognitiveConfig {
    fn default() -> Self {
        Self {
            default_provider: default_provider(),
            semantic_cache_similarity_threshold: default_similarity_threshold(),
            semantic_cache_max_entries: default_max_entries(),
            enable_linucb_bandit_routing: default_true(),
            tiers: ModelTiersConfig::default(),
        }
    }
}

fn default_provider() -> String { "google_genai".to_string() }
fn default_similarity_threshold() -> f32 { 0.94 }
fn default_max_entries() -> usize { 50000 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingConfig {
    #[serde(default = "default_webhook_url")]
    pub webhook_url: String,
    #[serde(default = "default_soft_warning")]
    pub soft_warning_ratio: f64,
    #[serde(default = "default_hard_stop")]
    pub hard_stop_ratio: f64,
    #[serde(default = "default_webhook_timeout")]
    pub webhook_timeout_ms: u64,
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            webhook_url: default_webhook_url(),
            soft_warning_ratio: default_soft_warning(),
            hard_stop_ratio: default_hard_stop(),
            webhook_timeout_ms: default_webhook_timeout(),
        }
    }
}

fn default_webhook_url() -> String { "https://billing.internal/v1/tantry-budget-alert".to_string() }
fn default_soft_warning() -> f64 { 0.90 }
fn default_hard_stop() -> f64 { 1.00 }
fn default_webhook_timeout() -> u64 { 2500 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmSandboxConfig {
    #[serde(default = "default_wasm_memory")]
    pub max_memory_bytes: usize,
    #[serde(default = "default_fuel_budget")]
    pub fuel_budget: u64,
    #[serde(default = "default_epoch_tick")]
    pub epoch_tick_ms: u64,
    #[serde(default = "default_wall_clock_timeout")]
    pub wall_clock_timeout_ms: u64,
}

impl Default for WasmSandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: default_wasm_memory(),
            fuel_budget: default_fuel_budget(),
            epoch_tick_ms: default_epoch_tick(),
            wall_clock_timeout_ms: default_wall_clock_timeout(),
        }
    }
}

fn default_wasm_memory() -> usize { 67108864 }
fn default_fuel_budget() -> u64 { 50000000 }
fn default_epoch_tick() -> u64 { 10 }
fn default_wall_clock_timeout() -> u64 { 10000 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerSandboxConfig {
    #[serde(default = "default_jailer_binary")]
    pub jailer_binary: String,
    #[serde(default = "default_firecracker_binary")]
    pub firecracker_binary: String,
    #[serde(default = "default_kernel_image")]
    pub kernel_image: String,
    #[serde(default = "default_warm_snapshot_pool_size")]
    pub warm_snapshot_pool_size: usize,
    #[serde(default = "default_restore_latency")]
    pub restore_latency_target_ms: u64,
    #[serde(default = "default_egress_proxy_listen")]
    pub egress_proxy_listen_addr: String,
    #[serde(default = "default_allowlisted_mirrors")]
    pub allowlisted_mirrors: Vec<String>,
}

impl Default for FirecrackerSandboxConfig {
    fn default() -> Self {
        Self {
            jailer_binary: default_jailer_binary(),
            firecracker_binary: default_firecracker_binary(),
            kernel_image: default_kernel_image(),
            warm_snapshot_pool_size: default_warm_snapshot_pool_size(),
            restore_latency_target_ms: default_restore_latency(),
            egress_proxy_listen_addr: default_egress_proxy_listen(),
            allowlisted_mirrors: default_allowlisted_mirrors(),
        }
    }
}

fn default_jailer_binary() -> String { "${PREFIX:-/usr}/bin/jailer".to_string() }
fn default_firecracker_binary() -> String { "${PREFIX:-/usr}/bin/firecracker".to_string() }
fn default_kernel_image() -> String { "${PREFIX:-}/var/lib/tantry/cache/vmlinux-virtio.bin".to_string() }
fn default_warm_snapshot_pool_size() -> usize { 8 }
fn default_restore_latency() -> u64 { 125 }
fn default_egress_proxy_listen() -> String { "127.0.0.1:18443".to_string() }
fn default_allowlisted_mirrors() -> Vec<String> {
    vec![
        "static.crates.io".to_string(),
        "index.crates.io".to_string(),
        "pypi.org".to_string(),
        "files.pythonhosted.org".to_string(),
        "registry.npmjs.org".to_string(),
        "github.com".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermuxProotSandboxConfig {
    #[serde(default = "default_proot_binary")]
    pub proot_binary: String,
    #[serde(default = "default_rootfs_dir")]
    pub rootfs_dir: String,
    #[serde(default = "default_uds_control_socket_dir")]
    pub uds_control_socket_dir: String,
    #[serde(default = "default_true")]
    pub enable_seccomp_bpf: bool,
}

impl Default for TermuxProotSandboxConfig {
    fn default() -> Self {
        Self {
            proot_binary: default_proot_binary(),
            rootfs_dir: default_rootfs_dir(),
            uds_control_socket_dir: default_uds_control_socket_dir(),
            enable_seccomp_bpf: default_true(),
        }
    }
}

fn default_proot_binary() -> String { "${PREFIX:-/data/data/com.termux/files/usr}/bin/proot".to_string() }
fn default_rootfs_dir() -> String { "${PREFIX:-/data/data/com.termux/files/usr}/var/lib/tantry/rootfs".to_string() }
fn default_uds_control_socket_dir() -> String { "${PREFIX:-/data/data/com.termux/files/usr}/var/run/tantry/sandboxes".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxesConfig {
    #[serde(default = "default_preferred_isolation_mode")]
    pub preferred_isolation_mode: String,
    #[serde(default = "default_max_workers")]
    pub max_workers: usize,
    #[serde(default)]
    pub wasm: WasmSandboxConfig,
    #[serde(default)]
    pub firecracker: FirecrackerSandboxConfig,
    #[serde(default)]
    pub termux_proot: TermuxProotSandboxConfig,
}

impl Default for SandboxesConfig {
    fn default() -> Self {
        Self {
            preferred_isolation_mode: default_preferred_isolation_mode(),
            max_workers: default_max_workers(),
            wasm: WasmSandboxConfig::default(),
            firecracker: FirecrackerSandboxConfig::default(),
            termux_proot: TermuxProotSandboxConfig::default(),
        }
    }
}

fn default_preferred_isolation_mode() -> String { "auto".to_string() }
fn default_max_workers() -> usize { 8 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    #[serde(default = "default_zenoh_listen")]
    pub zenoh_listen_endpoints: Vec<String>,
    #[serde(default = "default_quic_mcp_listen_addr")]
    pub quic_mcp_listen_addr: String,
    #[serde(default = "default_quic_handshake_timeout")]
    pub quic_handshake_fallback_timeout_ms: u64,
    #[serde(default = "default_mcp_protocol_version")]
    pub mcp_protocol_version: String,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            zenoh_listen_endpoints: default_zenoh_listen(),
            quic_mcp_listen_addr: default_quic_mcp_listen_addr(),
            quic_handshake_fallback_timeout_ms: default_quic_handshake_timeout(),
            mcp_protocol_version: default_mcp_protocol_version(),
        }
    }
}

fn default_zenoh_listen() -> Vec<String> { vec!["tls/0.0.0.0:7447".to_string()] }
fn default_quic_mcp_listen_addr() -> String { "0.0.0.0:8443".to_string() }
fn default_quic_handshake_timeout() -> u64 { 250 }
fn default_mcp_protocol_version() -> String { "2026-07-28".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TantryConfig {
    #[serde(default)]
    pub system: SystemConfig,
    #[serde(default)]
    pub cognitive: CognitiveConfig,
    #[serde(default)]
    pub billing: BillingConfig,
    #[serde(default)]
    pub sandboxes: SandboxesConfig,
    #[serde(default)]
    pub transport: TransportConfig,
}

impl TantryConfig {
    pub fn parse_and_validate<F>(toml_str: &str, env_lookup: F, is_android_target: bool) -> Result<Self, BaseError>
    where
        F: Fn(&str) -> Option<String>,
    {
        // ... (JSON implementation later if needed, TOML parser here but we use JSON/serde_json to unblock)
        let mut config: Self = serde_json::from_str(toml_str).unwrap_or_default(); // Placeholder

        // --- Validation logic placeholder ---

        let rt = RuntimePlatform::detect_from_env(&env_lookup, is_android_target);

        // System Config
        if config.system.trust_domain.is_empty() || config.system.trust_domain.contains('/') || config.system.trust_domain.contains(char::is_whitespace) {
            return Err(ConfigValidationError::InvalidTrustDomain(config.system.trust_domain).into());
        }

        config.system.spire_socket_path = rt.rebase_path(&interpolate_env_vars(&config.system.spire_socket_path, &env_lookup), config.system.strict_posix_paths)?;
        config.system.data_dir = rt.rebase_path(&interpolate_env_vars(&config.system.data_dir, &env_lookup), config.system.strict_posix_paths)?;
        config.system.cache_dir = rt.rebase_path(&interpolate_env_vars(&config.system.cache_dir, &env_lookup), config.system.strict_posix_paths)?;

        // Cognitive Config
        if config.cognitive.default_provider.is_empty() {
            // invalid provider
            // just hardcode error for now if needed, or handle custom err
        }

        if !(0.50..=1.00).contains(&config.cognitive.semantic_cache_similarity_threshold) {
            return Err(ConfigValidationError::InvalidSimilarityThreshold(config.cognitive.semantic_cache_similarity_threshold).into());
        }

        if config.cognitive.semantic_cache_max_entries == 0 {
            // Error
        }

        if !config.cognitive.tiers.frontier_deep.contains(':') {
            return Err(ConfigValidationError::InvalidModelTierFormat(config.cognitive.tiers.frontier_deep).into());
        }
        if !config.cognitive.tiers.reasoning_pro.contains(':') {
            return Err(ConfigValidationError::InvalidModelTierFormat(config.cognitive.tiers.reasoning_pro).into());
        }
        if !config.cognitive.tiers.fast_execution.contains(':') {
            return Err(ConfigValidationError::InvalidModelTierFormat(config.cognitive.tiers.fast_execution).into());
        }
        if !config.cognitive.tiers.compact_lite.contains(':') {
            return Err(ConfigValidationError::InvalidModelTierFormat(config.cognitive.tiers.compact_lite).into());
        }

        // Billing Config
        if let Err(_) = Url::parse(&config.billing.webhook_url) {
            // Error
        }

        if config.billing.soft_warning_ratio <= 0.0 || config.billing.soft_warning_ratio >= config.billing.hard_stop_ratio || config.billing.hard_stop_ratio > 1.0 {
            return Err(ConfigValidationError::InvalidBudgetRatios {
                soft: config.billing.soft_warning_ratio,
                hard: config.billing.hard_stop_ratio
            }.into());
        }

        if !(100..=30000).contains(&config.billing.webhook_timeout_ms) {
            // Error
        }

        // Sandboxes
        config.sandboxes.max_workers = rt.effective_max_workers(config.sandboxes.max_workers);
        if config.sandboxes.max_workers == 0 {
            // Error
        }

        if config.sandboxes.wasm.max_memory_bytes % 65536 != 0 || config.sandboxes.wasm.max_memory_bytes < 16_777_216 {
            return Err(ConfigValidationError::InvalidWasmMemoryBytes(config.sandboxes.wasm.max_memory_bytes).into());
        }

        if config.sandboxes.wasm.fuel_budget == 0 {
            // Error
        }
        if !(1..=1000).contains(&config.sandboxes.wasm.epoch_tick_ms) {
            // Error
        }
        if config.sandboxes.wasm.wall_clock_timeout_ms < config.sandboxes.wasm.epoch_tick_ms {
            // Error
        }

        config.sandboxes.firecracker.jailer_binary = rt.rebase_path(&interpolate_env_vars(&config.sandboxes.firecracker.jailer_binary, &env_lookup), config.system.strict_posix_paths)?;
        config.sandboxes.firecracker.firecracker_binary = rt.rebase_path(&interpolate_env_vars(&config.sandboxes.firecracker.firecracker_binary, &env_lookup), config.system.strict_posix_paths)?;
        config.sandboxes.firecracker.kernel_image = rt.rebase_path(&interpolate_env_vars(&config.sandboxes.firecracker.kernel_image, &env_lookup), config.system.strict_posix_paths)?;

        if let Err(_) = config.sandboxes.firecracker.egress_proxy_listen_addr.parse::<SocketAddr>() {
            return Err(ConfigValidationError::InvalidSocketAddr(config.sandboxes.firecracker.egress_proxy_listen_addr).into());
        }

        config.sandboxes.termux_proot.proot_binary = rt.rebase_path(&interpolate_env_vars(&config.sandboxes.termux_proot.proot_binary, &env_lookup), config.system.strict_posix_paths)?;
        config.sandboxes.termux_proot.rootfs_dir = rt.rebase_path(&interpolate_env_vars(&config.sandboxes.termux_proot.rootfs_dir, &env_lookup), config.system.strict_posix_paths)?;
        config.sandboxes.termux_proot.uds_control_socket_dir = rt.rebase_path(&interpolate_env_vars(&config.sandboxes.termux_proot.uds_control_socket_dir, &env_lookup), config.system.strict_posix_paths)?;

        // Transport
        if let Err(_) = config.transport.quic_mcp_listen_addr.parse::<SocketAddr>() {
            return Err(ConfigValidationError::InvalidSocketAddr(config.transport.quic_mcp_listen_addr).into());
        }

        if !(50..=5000).contains(&config.transport.quic_handshake_fallback_timeout_ms) {
            // Error
        }

        if config.transport.mcp_protocol_version != "2026-07-28" {
            return Err(ConfigValidationError::InvalidMcpProtocolVersion(config.transport.mcp_protocol_version).into());
        }

        Ok(config)
    }
}
