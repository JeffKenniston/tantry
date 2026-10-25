use crate::error::ConfigValidationError;
use crate::path::validate_and_normalize_path;
use crate::platform::{interpolate_env_vars, RuntimePlatform};

#[derive(Debug, Clone, PartialEq)]
pub struct TantryConfig {
    pub system: SystemConfig,
    pub cognitive: CognitiveConfig,
    pub model_tiers: ModelTiersConfig,
    pub billing: BillingConfig,
    pub sandboxes: SandboxesConfig,
    pub transport: TransportConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SystemConfig {
    pub strict_posix_paths: bool,
    pub trust_domain: String,
    pub data_dir: String,
    pub max_workers: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CognitiveConfig {
    pub similarity_threshold: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelTiersConfig {
    pub default_tier: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BillingConfig {
    pub budget_ratio: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SandboxesConfig {
    pub wasm: WasmSandboxConfig,
    pub firecracker: FirecrackerSandboxConfig,
    pub termux_proot: TermuxProotSandboxConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WasmSandboxConfig {
    pub memory_pages: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FirecrackerSandboxConfig {
    pub kernel_image_path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TermuxProotSandboxConfig {
    pub rootfs_path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransportConfig {
    pub mcp_protocol_version: String,
    pub socket_address: String,
}

impl TantryConfig {
    pub fn parse_and_validate(mut self, platform: &RuntimePlatform) -> Result<Self, ConfigValidationError> {
        // 1. Validate System Config
        if self.system.trust_domain.is_empty() {
            return Err(ConfigValidationError::InvalidTrustDomain("Trust domain cannot be empty".to_string()));
        }

        let interpolated_data_dir = interpolate_env_vars(&self.system.data_dir);
        let rebased_data_dir = platform.rebase_path(&interpolated_data_dir, self.system.strict_posix_paths);
        self.system.data_dir = validate_and_normalize_path(&rebased_data_dir)?;

        self.system.max_workers = platform.effective_max_workers(self.system.max_workers);

        // 2. Validate Cognitive Config
        if self.cognitive.similarity_threshold < 0.0 || self.cognitive.similarity_threshold > 1.0 {
            return Err(ConfigValidationError::InvalidSimilarityThreshold);
        }

        // 3. Validate Billing Config
        if self.billing.budget_ratio < 0.0 {
            return Err(ConfigValidationError::InvalidBudgetRatio);
        }

        // Validate Model Tiers
        if !self.model_tiers.default_tier.starts_with("tier-") {
             return Err(ConfigValidationError::InvalidModelTierFormat);
        }

        // 4. Validate Sandbox Configs
        if self.sandboxes.wasm.memory_pages == 0 || self.sandboxes.wasm.memory_pages % 2 != 0 {
             return Err(ConfigValidationError::InvalidWasmMemory);
        }

        let interp_kernel = interpolate_env_vars(&self.sandboxes.firecracker.kernel_image_path);
        let rebased_kernel = platform.rebase_path(&interp_kernel, self.system.strict_posix_paths);
        self.sandboxes.firecracker.kernel_image_path = validate_and_normalize_path(&rebased_kernel)?;

        let interp_rootfs = interpolate_env_vars(&self.sandboxes.termux_proot.rootfs_path);
        let rebased_rootfs = platform.rebase_path(&interp_rootfs, self.system.strict_posix_paths);
        self.sandboxes.termux_proot.rootfs_path = validate_and_normalize_path(&rebased_rootfs)?;

        // 5. Validate Transport Config
        if !self.transport.mcp_protocol_version.starts_with("2026-07-28") {
            return Err(ConfigValidationError::InvalidMcpProtocolVersion(self.transport.mcp_protocol_version));
        }

        if self.transport.socket_address.parse::<std::net::SocketAddr>().is_err() {
            return Err(ConfigValidationError::InvalidSocketAddress(self.transport.socket_address));
        }

        Ok(self)
    }
}
