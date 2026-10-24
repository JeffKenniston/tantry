
/// Tier of sandbox isolation detected on the host
#[derive(Debug, PartialEq, Eq)]
pub enum IsolationTier {
    /// Firecracker MicroVM with Linux landlock
    FirecrackerKvm,
    /// Termux PRoot with seccomp-bpf
    TermuxProotUds,
    /// WASI 0.3 fallback
    Wasi03AndSanitizedProcessGroup,
}

/// Configuration for sandboxes
#[derive(Debug)]
pub struct SandboxesConfig {
    /// Max memory
    pub max_memory_bytes: u64,
}

/// Platform capabilities
#[derive(Debug)]
pub struct RuntimePlatform {
    /// Has Android Termux features
    pub is_android_termux: bool,
}

/// Detects available host capabilities and returns the optimal IsolationTier
pub struct HostCapabilityProbe;

impl HostCapabilityProbe {
    /// Detect optimal sandbox tier
    pub fn detect(_config: &SandboxesConfig, platform: &RuntimePlatform) -> IsolationTier {
        if let Ok(_file) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm") {
            // we'd also check for firecracker/jailer bins
            return IsolationTier::FirecrackerKvm;
        }

        if platform.is_android_termux {
            return IsolationTier::TermuxProotUds;
        }

        IsolationTier::Wasi03AndSanitizedProcessGroup
    }
}
