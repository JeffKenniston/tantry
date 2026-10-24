use crate::error::{BaseError, ConfigValidationError};
use crate::platform::{RuntimePlatform, interpolate_env_vars};
use serde::Deserialize;
use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
/// SystemConfig struct
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

#[derive(Debug, Deserialize)]
/// CognitiveConfig struct
pub struct CognitiveConfig {
    #[serde(default = "default_cognitive_provider")]
    pub default_provider: String,
    #[serde(default = "default_similarity_threshold")]
    pub semantic_cache_similarity_threshold: f32,
    #[serde(default = "default_semantic_cache_max_entries")]
    pub semantic_cache_max_entries: usize,
    #[serde(alias = "enable_ucb1_bandit_routing", default = "default_true")]
    pub enable_linucb_bandit_routing: bool,
    #[serde(default)]
    pub tiers: ModelTiersConfig,
}

#[derive(Debug, Deserialize)]
/// ModelTiersConfig struct
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

#[derive(Debug, Deserialize)]
/// BillingConfig struct
pub struct BillingConfig {
    #[serde(default = "default_webhook_url")]
    pub webhook_url: String,
    #[serde(default = "default_soft_warning_ratio")]
    pub soft_warning_ratio: f64,
    #[serde(default = "default_hard_stop_ratio")]
    pub hard_stop_ratio: f64,
    #[serde(default = "default_webhook_timeout_ms")]
    pub webhook_timeout_ms: u64,
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            webhook_url: default_webhook_url(),
            soft_warning_ratio: default_soft_warning_ratio(),
            hard_stop_ratio: default_hard_stop_ratio(),
            webhook_timeout_ms: default_webhook_timeout_ms(),
        }
    }
}

#[derive(Debug, Deserialize)]
/// WasmSandboxConfig struct
pub struct WasmSandboxConfig {
    #[serde(default = "default_wasm_max_memory_bytes")]
    pub max_memory_bytes: usize,
    #[serde(default = "default_wasm_fuel_budget")]
    pub fuel_budget: u64,
    #[serde(default = "default_wasm_epoch_tick_ms")]
    pub epoch_tick_ms: u64,
    #[serde(default = "default_wasm_wall_clock_timeout_ms")]
    pub wall_clock_timeout_ms: u64,
}

impl Default for WasmSandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: default_wasm_max_memory_bytes(),
            fuel_budget: default_wasm_fuel_budget(),
            epoch_tick_ms: default_wasm_epoch_tick_ms(),
            wall_clock_timeout_ms: default_wasm_wall_clock_timeout_ms(),
        }
    }
}

#[derive(Debug, Deserialize)]
/// FirecrackerSandboxConfig struct
pub struct FirecrackerSandboxConfig {
    #[serde(default = "default_firecracker_jailer_binary")]
    pub jailer_binary: String,
    #[serde(default = "default_firecracker_binary")]
    pub firecracker_binary: String,
    #[serde(default = "default_firecracker_kernel_image")]
    pub kernel_image: String,
    #[serde(default = "default_firecracker_warm_snapshot_pool_size")]
    pub warm_snapshot_pool_size: usize,
    #[serde(default = "default_firecracker_restore_latency_target_ms")]
    pub restore_latency_target_ms: u64,
    #[serde(default = "default_firecracker_egress_proxy_listen_addr")]
    pub egress_proxy_listen_addr: String,
    #[serde(default = "default_firecracker_allowlisted_mirrors")]
    pub allowlisted_mirrors: Vec<String>,
}

impl Default for FirecrackerSandboxConfig {
    fn default() -> Self {
        Self {
            jailer_binary: default_firecracker_jailer_binary(),
            firecracker_binary: default_firecracker_binary(),
            kernel_image: default_firecracker_kernel_image(),
            warm_snapshot_pool_size: default_firecracker_warm_snapshot_pool_size(),
            restore_latency_target_ms: default_firecracker_restore_latency_target_ms(),
            egress_proxy_listen_addr: default_firecracker_egress_proxy_listen_addr(),
            allowlisted_mirrors: default_firecracker_allowlisted_mirrors(),
        }
    }
}

#[derive(Debug, Deserialize)]
/// TermuxProotSandboxConfig struct
pub struct TermuxProotSandboxConfig {
    #[serde(default = "default_termux_proot_binary")]
    pub proot_binary: String,
    #[serde(default = "default_termux_rootfs_dir")]
    pub rootfs_dir: String,
    #[serde(default = "default_termux_uds_control_socket_dir")]
    pub uds_control_socket_dir: String,
    #[serde(default = "default_true")]
    pub enable_seccomp_bpf: bool,
}

impl Default for TermuxProotSandboxConfig {
    fn default() -> Self {
        Self {
            proot_binary: default_termux_proot_binary(),
            rootfs_dir: default_termux_rootfs_dir(),
            uds_control_socket_dir: default_termux_uds_control_socket_dir(),
            enable_seccomp_bpf: default_true(),
        }
    }
}

#[derive(Debug, Deserialize)]
/// SandboxesConfig struct
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

#[derive(Debug, Deserialize)]
/// TransportConfig struct
pub struct TransportConfig {
    #[serde(default = "default_zenoh_listen_endpoints")]
    pub zenoh_listen_endpoints: Vec<String>,
    #[serde(default = "default_quic_mcp_listen_addr")]
    pub quic_mcp_listen_addr: String,
    #[serde(default = "default_quic_handshake_fallback_timeout_ms")]
    pub quic_handshake_fallback_timeout_ms: u64,
    #[serde(default = "default_mcp_protocol_version")]
    pub mcp_protocol_version: String,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            zenoh_listen_endpoints: default_zenoh_listen_endpoints(),
            quic_mcp_listen_addr: default_quic_mcp_listen_addr(),
            quic_handshake_fallback_timeout_ms: default_quic_handshake_fallback_timeout_ms(),
            mcp_protocol_version: default_mcp_protocol_version(),
        }
    }
}

#[derive(Debug, Deserialize)]
/// TantryConfig struct
pub struct TantryConfig {
    #[serde(default = "default_system_config")]
    pub system: SystemConfig,
    #[serde(default = "default_cognitive_config")]
    pub cognitive: CognitiveConfig,
    #[serde(default)]
    pub billing: BillingConfig,
    #[serde(default)]
    pub sandboxes: SandboxesConfig,
    #[serde(default)]
    pub transport: TransportConfig,
}

// Defaults
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_trust_domain() -> String {
    "tantry.internal".to_string()
}
fn default_spire_socket_path() -> String {
    "${PREFIX:-}/run/spire/sockets/agent.sock".to_string()
}
fn default_data_dir() -> String {
    "${PREFIX:-}/var/lib/tantry/data".to_string()
}
fn default_cache_dir() -> String {
    "${PREFIX:-}/var/lib/tantry/cache".to_string()
}
fn default_cognitive_provider() -> String {
    "google_genai".to_string()
}
fn default_similarity_threshold() -> f32 {
    0.94
}
fn default_semantic_cache_max_entries() -> usize {
    50000
}
fn default_frontier_deep() -> String {
    "google_genai:gemini-4-argon".to_string()
}
fn default_reasoning_pro() -> String {
    "google_genai:gemini-3.1-pro".to_string()
}
fn default_fast_execution() -> String {
    "google_genai:gemini-3.8-flash".to_string()
}
fn default_compact_lite() -> String {
    "google_genai:gemini-3.5-flash-lite".to_string()
}
fn default_webhook_url() -> String {
    "https://billing.internal/v1/tantry-budget-alert".to_string()
}
fn default_soft_warning_ratio() -> f64 {
    0.90
}
fn default_hard_stop_ratio() -> f64 {
    1.00
}
fn default_webhook_timeout_ms() -> u64 {
    2500
}
fn default_preferred_isolation_mode() -> String {
    "auto".to_string()
}
fn default_max_workers() -> usize {
    8
}
fn default_wasm_max_memory_bytes() -> usize {
    67108864
}
fn default_wasm_fuel_budget() -> u64 {
    50000000
}
fn default_wasm_epoch_tick_ms() -> u64 {
    10
}
fn default_wasm_wall_clock_timeout_ms() -> u64 {
    10000
}
fn default_firecracker_jailer_binary() -> String {
    "${PREFIX:-/usr}/bin/jailer".to_string()
}
fn default_firecracker_binary() -> String {
    "${PREFIX:-/usr}/bin/firecracker".to_string()
}
fn default_firecracker_kernel_image() -> String {
    "${PREFIX:-}/var/lib/tantry/cache/vmlinux-virtio.bin".to_string()
}
fn default_firecracker_warm_snapshot_pool_size() -> usize {
    8
}
fn default_firecracker_restore_latency_target_ms() -> u64 {
    125
}
fn default_firecracker_egress_proxy_listen_addr() -> String {
    "127.0.0.1:18443".to_string()
}
fn default_firecracker_allowlisted_mirrors() -> Vec<String> {
    vec![
        "static.crates.io".to_string(),
        "index.crates.io".to_string(),
        "pypi.org".to_string(),
        "files.pythonhosted.org".to_string(),
        "registry.npmjs.org".to_string(),
        "github.com".to_string(),
    ]
}
fn default_termux_proot_binary() -> String {
    "${PREFIX:-/data/data/com.termux/files/usr}/bin/proot".to_string()
}
fn default_termux_rootfs_dir() -> String {
    "${PREFIX:-/data/data/com.termux/files/usr}/var/lib/tantry/rootfs".to_string()
}
fn default_termux_uds_control_socket_dir() -> String {
    "${PREFIX:-/data/data/com.termux/files/usr}/var/run/tantry/sandboxes".to_string()
}
fn default_zenoh_listen_endpoints() -> Vec<String> {
    vec!["tls/0.0.0.0:7447".to_string()]
}
fn default_quic_mcp_listen_addr() -> String {
    "0.0.0.0:8443".to_string()
}
fn default_quic_handshake_fallback_timeout_ms() -> u64 {
    250
}
fn default_mcp_protocol_version() -> String {
    "2026-07-28".to_string()
}

fn default_system_config() -> SystemConfig {
    SystemConfig {
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

fn default_cognitive_config() -> CognitiveConfig {
    CognitiveConfig {
        default_provider: default_cognitive_provider(),
        semantic_cache_similarity_threshold: default_similarity_threshold(),
        semantic_cache_max_entries: default_semantic_cache_max_entries(),
        enable_linucb_bandit_routing: default_true(),
        tiers: ModelTiersConfig::default(),
    }
}

impl TantryConfig {
    /// parse_and_validate fn
    pub fn parse_and_validate<F>(
        toml_str: &str,
        env_lookup: F,
        is_android_target: bool,
    ) -> Result<Self, BaseError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut config: TantryConfig = match toml::from_str(toml_str) {
            Ok(c) => c,
            Err(e) => {
                return Err(ConfigValidationError::InvalidToml(format!(
                    "Failed to parse TOML: {}",
                    e
                ))
                .into());
            }
        };

        let platform = RuntimePlatform::detect_from_env(&env_lookup, is_android_target);

        // System
        if config.system.trust_domain.is_empty()
            || config.system.trust_domain.contains('/')
            || config.system.trust_domain.contains(char::is_whitespace)
        {
            return Err(
                ConfigValidationError::InvalidTrustDomain(config.system.trust_domain).into(),
            );
        }

        config.system.spire_socket_path =
            interpolate_env_vars(&config.system.spire_socket_path, &env_lookup);
        config.system.spire_socket_path = platform.rebase_path(
            &config.system.spire_socket_path,
            config.system.strict_posix_paths,
        )?;

        config.system.data_dir = interpolate_env_vars(&config.system.data_dir, &env_lookup);
        config.system.data_dir =
            platform.rebase_path(&config.system.data_dir, config.system.strict_posix_paths)?;

        config.system.cache_dir = interpolate_env_vars(&config.system.cache_dir, &env_lookup);
        config.system.cache_dir =
            platform.rebase_path(&config.system.cache_dir, config.system.strict_posix_paths)?;

        // Cognitive
        if config.cognitive.default_provider.is_empty() {
            return Err(ConfigValidationError::InvalidCognitiveProvider(
                "default_provider is empty".to_string(),
            )
            .into());
        }

        if config.cognitive.semantic_cache_similarity_threshold < 0.50
            || config.cognitive.semantic_cache_similarity_threshold > 1.00
        {
            return Err(ConfigValidationError::InvalidSimilarityThreshold(
                config.cognitive.semantic_cache_similarity_threshold,
            )
            .into());
        }

        if config.cognitive.semantic_cache_max_entries == 0 {
            return Err(ConfigValidationError::InvalidSemanticCacheMaxEntries(0).into());
        }

        let check_tier = |t: &str| -> Result<(), BaseError> {
            if !t.contains(':') {
                return Err(ConfigValidationError::InvalidModelTierFormat(t.to_string()).into());
            }
            Ok(())
        };
        check_tier(&config.cognitive.tiers.frontier_deep)?;
        check_tier(&config.cognitive.tiers.reasoning_pro)?;
        check_tier(&config.cognitive.tiers.fast_execution)?;
        check_tier(&config.cognitive.tiers.compact_lite)?;

        // Billing
        if !config.billing.webhook_url.starts_with("http://")
            && !config.billing.webhook_url.starts_with("https://")
        {
            return Err(ConfigValidationError::InvalidWebhookUrl(
                config.billing.webhook_url.clone(),
            )
            .into());
        }

        if config.billing.soft_warning_ratio <= 0.0
            || config.billing.soft_warning_ratio >= config.billing.hard_stop_ratio
            || config.billing.hard_stop_ratio > 1.0
        {
            return Err(ConfigValidationError::InvalidBudgetRatios {
                soft: config.billing.soft_warning_ratio,
                hard: config.billing.hard_stop_ratio,
            }
            .into());
        }

        if config.billing.webhook_timeout_ms < 100 || config.billing.webhook_timeout_ms > 30000 {
            return Err(ConfigValidationError::InvalidWebhookTimeoutMs(
                config.billing.webhook_timeout_ms,
            )
            .into());
        }

        // Sandboxes
        if !["auto", "firecracker", "termux_proot", "wasm_only"]
            .contains(&config.sandboxes.preferred_isolation_mode.as_str())
        {
            return Err(ConfigValidationError::InvalidIsolationMode(
                config.sandboxes.preferred_isolation_mode.clone(),
            )
            .into());
        }

        if config.sandboxes.max_workers == 0 {
            return Err(ConfigValidationError::InvalidMaxWorkers(0).into());
        }
        config.sandboxes.max_workers = platform.effective_max_workers(config.sandboxes.max_workers);

        #[allow(clippy::manual_is_multiple_of)]
        if config.sandboxes.wasm.max_memory_bytes % 65536 != 0
            || config.sandboxes.wasm.max_memory_bytes < 16777216
        {
            return Err(ConfigValidationError::InvalidWasmMemoryBytes(
                config.sandboxes.wasm.max_memory_bytes,
            )
            .into());
        }

        if config.sandboxes.wasm.fuel_budget == 0 {
            return Err(ConfigValidationError::InvalidWasmFuelBudget(0).into());
        }

        if config.sandboxes.wasm.epoch_tick_ms < 1 || config.sandboxes.wasm.epoch_tick_ms > 1000 {
            return Err(ConfigValidationError::InvalidWasmEpochTickMs(
                config.sandboxes.wasm.epoch_tick_ms,
            )
            .into());
        }

        if config.sandboxes.wasm.wall_clock_timeout_ms < config.sandboxes.wasm.epoch_tick_ms {
            return Err(ConfigValidationError::InvalidWasmWallClockTimeoutMs(
                config.sandboxes.wasm.wall_clock_timeout_ms,
            )
            .into());
        }

        config.sandboxes.firecracker.jailer_binary =
            interpolate_env_vars(&config.sandboxes.firecracker.jailer_binary, &env_lookup);
        config.sandboxes.firecracker.jailer_binary = platform.rebase_path(
            &config.sandboxes.firecracker.jailer_binary,
            config.system.strict_posix_paths,
        )?;

        config.sandboxes.firecracker.firecracker_binary = interpolate_env_vars(
            &config.sandboxes.firecracker.firecracker_binary,
            &env_lookup,
        );
        config.sandboxes.firecracker.firecracker_binary = platform.rebase_path(
            &config.sandboxes.firecracker.firecracker_binary,
            config.system.strict_posix_paths,
        )?;

        config.sandboxes.firecracker.kernel_image =
            interpolate_env_vars(&config.sandboxes.firecracker.kernel_image, &env_lookup);
        config.sandboxes.firecracker.kernel_image = platform.rebase_path(
            &config.sandboxes.firecracker.kernel_image,
            config.system.strict_posix_paths,
        )?;

        if SocketAddr::from_str(&config.sandboxes.firecracker.egress_proxy_listen_addr).is_err() {
            return Err(ConfigValidationError::InvalidSocketAddr(
                config
                    .sandboxes
                    .firecracker
                    .egress_proxy_listen_addr
                    .clone(),
            )
            .into());
        }

        config.sandboxes.termux_proot.proot_binary =
            interpolate_env_vars(&config.sandboxes.termux_proot.proot_binary, &env_lookup);
        config.sandboxes.termux_proot.proot_binary = platform.rebase_path(
            &config.sandboxes.termux_proot.proot_binary,
            config.system.strict_posix_paths,
        )?;

        config.sandboxes.termux_proot.rootfs_dir =
            interpolate_env_vars(&config.sandboxes.termux_proot.rootfs_dir, &env_lookup);
        config.sandboxes.termux_proot.rootfs_dir = platform.rebase_path(
            &config.sandboxes.termux_proot.rootfs_dir,
            config.system.strict_posix_paths,
        )?;

        config.sandboxes.termux_proot.uds_control_socket_dir = interpolate_env_vars(
            &config.sandboxes.termux_proot.uds_control_socket_dir,
            &env_lookup,
        );
        config.sandboxes.termux_proot.uds_control_socket_dir = platform.rebase_path(
            &config.sandboxes.termux_proot.uds_control_socket_dir,
            config.system.strict_posix_paths,
        )?;

        // Transport
        if config.transport.zenoh_listen_endpoints.is_empty() {
            return Err(ConfigValidationError::InvalidZenohListenEndpoints.into());
        }

        if SocketAddr::from_str(&config.transport.quic_mcp_listen_addr).is_err() {
            return Err(ConfigValidationError::InvalidSocketAddr(
                config.transport.quic_mcp_listen_addr.clone(),
            )
            .into());
        }

        if config.transport.quic_handshake_fallback_timeout_ms < 50
            || config.transport.quic_handshake_fallback_timeout_ms > 5000
        {
            return Err(
                ConfigValidationError::InvalidQuicHandshakeFallbackTimeoutMs(
                    config.transport.quic_handshake_fallback_timeout_ms,
                )
                .into(),
            );
        }

        if config.transport.mcp_protocol_version != "2026-07-28" {
            return Err(ConfigValidationError::InvalidMcpProtocolVersion(
                config.transport.mcp_protocol_version.clone(),
            )
            .into());
        }

        Ok(config)
    }
}
