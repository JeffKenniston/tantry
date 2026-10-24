use crate::error::BackendError;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// Manages a pool of termux zygotes
#[derive(Debug)]
pub struct TermuxZygotePool {
    /// Max workers allowed (<= 12 total OS processes)
    pub max_workers: usize,
}

impl TermuxZygotePool {
    /// Create a new pool
    pub fn new(max_workers: usize) -> Self {
        Self {
            max_workers: std::cmp::min(max_workers, 8),
        } // leaving room for up to 12 total
    }

    /// Reaps a timed-out process group and all descendants
    pub fn reap_process_group(pgid: i32) -> Result<(), BackendError> {
        let pid = Pid::from_raw(-pgid); // send to pgid
        match kill(pid, Signal::SIGKILL) {
            Ok(_) => Ok(()),
            Err(nix::errno::Errno::ESRCH) => Ok(()), // process not found is ok
            Err(e) => Err(BackendError::Execution(format!("kill failed: {}", e))),
        }
    }
}
