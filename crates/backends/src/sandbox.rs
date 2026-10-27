use nix::sys::signal::{kill, Signal};
use nix::unistd::{setsid, Pid};
use std::process::Command;
use std::os::unix::process::CommandExt;

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
        if let Ok(_file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
        {
            // we'd also check for firecracker/jailer bins
            return IsolationTier::FirecrackerKvm;
        }

        if platform.is_android_termux {
            return IsolationTier::TermuxProotUds;
        }

        IsolationTier::Wasi03AndSanitizedProcessGroup
    }
}

/// Secure process execution helper
pub struct SecureProcess;

impl SecureProcess {
    /// Spawns a process with a new session ID for process group isolation
    pub fn spawn_with_setsid(mut cmd: Command) -> std::io::Result<std::process::Child> {
        unsafe {
            cmd.pre_exec(|| {
                setsid().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                Ok(())
            });
        }
        cmd.spawn()
    }

    /// Reaps a timed-out process group and all descendants
    pub fn reap_timeout_pgid(pgid: i32) -> Result<(), String> {
        let pid = Pid::from_raw(-pgid);
        match kill(pid, Signal::SIGKILL) {
            Ok(_) => Ok(()),
            Err(nix::errno::Errno::ESRCH) => Ok(()), // process not found is ok
            Err(e) => Err(format!("kill failed: {}", e)),
        }
    }
}
