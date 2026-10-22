use crate::error::{BaseError, ConfigValidationError};
use crate::path::PosixPath;
use crate::platform::{interpolate_env_vars, RuntimePlatform};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TantryConfig {
    pub system: SystemConfig,
    pub cognitive: CognitiveConfig,
    pub model_tiers: ModelTiersConfig,
    pub billing: BillingConfig,
    pub sandboxes: SandboxesConfig,
    pub transport: TransportConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemConfig {
    pub trust_domain: String,
    pub strict_posix_paths: bool,
    pub data_dir: PosixPath,
    pub run_dir: PosixPath,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CognitiveConfig {
    pub default_system_prompt: String,
    pub memory_ttl_seconds: u32,
    pub similarity_threshold: f32,
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
    pub soft_limit_usd: f64,
    pub hard_limit_usd: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxesConfig {
    pub max_workers: usize,
    pub wasm: WasmSandboxConfig,
    pub firecracker: FirecrackerSandboxConfig,
    pub termux_proot: TermuxProotSandboxConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WasmSandboxConfig {
    pub max_memory_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FirecrackerSandboxConfig {
    pub kernel_image_path: PosixPath,
    pub rootfs_path: PosixPath,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TermuxProotSandboxConfig {
    pub guest_rootfs_path: PosixPath,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransportConfig {
    pub mcp_protocol_version: String,
    pub listen_addr: String,
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

        if !num::Integer::is_multiple_of(&self.sandboxes.wasm.max_memory_bytes, &65536) {
            return Err(ConfigValidationError::InvalidWasmMemoryBytes(
                self.sandboxes.wasm.max_memory_bytes,
            )
            .into());
        }

        if !self.transport.mcp_protocol_version.starts_with("2024-") && !self.transport.mcp_protocol_version.starts_with("2026-") {
            return Err(ConfigValidationError::InvalidMcpProtocolVersion(
                self.transport.mcp_protocol_version.clone(),
            )
            .into());
        }

        if self.transport.listen_addr.parse::<std::net::SocketAddr>().is_err() {
            return Err(ConfigValidationError::InvalidSocketAddr(self.transport.listen_addr.clone()).into());
        }

        self.sandboxes.max_workers = platform.effective_max_workers(self.sandboxes.max_workers);

        self.system.data_dir =
            platform.rebase_path(&self.system.data_dir, self.system.strict_posix_paths)?;
        self.system.run_dir =
            platform.rebase_path(&self.system.run_dir, self.system.strict_posix_paths)?;

        Ok(())
    }
}
