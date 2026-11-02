use nix::sys::signal::{Signal, kill};
use nix::unistd::{Pid, setsid};
use std::os::unix::process::CommandExt;
use std::process::Command;

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
                setsid()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
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

pub struct AdaptiveSandboxRunner {
    pub env_cap: std::sync::Arc<permissions::EnvCapability>,
}
pub struct RunnerRequest {
    pub timeout_ms: u64,
}

impl AdaptiveSandboxRunner {
    pub async fn execute(&self, mut cmd: tokio::process::Command, req: RunnerRequest) -> Result<std::process::ExitStatus, crate::error::BackendError> {
        let env_vars = std::env::vars();
        let scrubbed = self.env_cap.scrub_host_env(env_vars);
        cmd.env_clear();
        cmd.envs(scrubbed);

        unsafe {
            cmd.pre_exec(|| {
                nix::unistd::setsid().map_err(std::io::Error::from)?;
                Ok(())
            });
        }

        let mut child = cmd.spawn().map_err(|e| crate::error::BackendError::Io(e.to_string()))?;
        let child_pid = child.id().unwrap();

        let res = tokio::time::timeout(std::time::Duration::from_millis(req.timeout_ms), child.wait()).await;

        match res {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(e)) => Err(crate::error::BackendError::Io(e.to_string())),
            Err(_) => {
                let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(-(child_pid as i32)), nix::sys::signal::Signal::SIGKILL);
                let _ = child.wait().await;
                Err(crate::error::BackendError::SandboxTimeout { timeout_ms: req.timeout_ms, pgid: child_pid as i32 })
            }
        }
    }
}
