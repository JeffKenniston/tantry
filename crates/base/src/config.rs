use crate::error::{BaseError, ConfigValidationError};
use crate::path::PosixPath;
use crate::platform::RuntimePlatform;

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
    pub trust_domain: String,
    pub strict_posix_paths: bool,
    pub data_dir: PosixPath,
    pub run_dir: PosixPath,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CognitiveConfig {
    pub default_system_prompt: String,
    pub memory_ttl_seconds: u32,
    pub similarity_threshold: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelTiersConfig {
    pub frontier_deep: String,
    pub reasoning_pro: String,
    pub fast_execution: String,
    pub compact_lite: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BillingConfig {
    pub soft_limit_usd: f64,
    pub hard_limit_usd: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SandboxesConfig {
    pub max_workers: usize,
    pub wasm: WasmSandboxConfig,
    pub firecracker: FirecrackerSandboxConfig,
    pub termux_proot: TermuxProotSandboxConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WasmSandboxConfig {
    pub max_memory_bytes: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FirecrackerSandboxConfig {
    pub kernel_image_path: PosixPath,
    pub rootfs_path: PosixPath,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TermuxProotSandboxConfig {
    pub guest_rootfs_path: PosixPath,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransportConfig {
    pub mcp_protocol_version: String,
    pub listen_addr: String,
}

impl TantryConfig {
    pub fn parse_and_validate<F>(
        _toml_str: &str,
        env_lookup: F,
        is_android_target: bool,
    ) -> Result<Self, BaseError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let platform = RuntimePlatform::detect_from_env(env_lookup, is_android_target);
        let _ = platform;
        Err(BaseError::Config(
            ConfigValidationError::InvalidTrustDomain(
                "TOML parsing not fully implemented in AST stub".into(),
            ),
        ))
    }

    pub fn validate(&mut self, platform: &RuntimePlatform) -> Result<(), BaseError> {
        if self.system.trust_domain.is_empty() {
            return Err(ConfigValidationError::InvalidTrustDomain(
                self.system.trust_domain.clone(),
            )
            .into());
        }

        if self.cognitive.similarity_threshold < 0.0 || self.cognitive.similarity_threshold > 1.0 {
            return Err(ConfigValidationError::InvalidSimilarityThreshold(
                self.cognitive.similarity_threshold,
            )
            .into());
        }

        if self.billing.soft_limit_usd > self.billing.hard_limit_usd {
            return Err(ConfigValidationError::InvalidBudgetRatios {
                soft: self.billing.soft_limit_usd,
                hard: self.billing.hard_limit_usd,
            }
            .into());
        }

        if self.sandboxes.wasm.max_memory_bytes % 65536 != 0 {
            return Err(ConfigValidationError::InvalidWasmMemoryBytes(
                self.sandboxes.wasm.max_memory_bytes,
            )
            .into());
        }

        self.sandboxes.max_workers = platform.effective_max_workers(self.sandboxes.max_workers);

        self.system.data_dir =
            platform.rebase_path(&self.system.data_dir, self.system.strict_posix_paths)?;
        self.system.run_dir =
            platform.rebase_path(&self.system.run_dir, self.system.strict_posix_paths)?;

        Ok(())
    }
}
