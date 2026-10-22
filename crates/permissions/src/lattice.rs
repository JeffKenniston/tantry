use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PermissionMode {
    Allow = 0,
    Interrupt = 1,
    Deny = 2,
}

impl PermissionMode {
    /// Least Upper Bound / Join ($\sqcup$)
    /// Computes the supremum in the join-semilattice.
    pub fn join(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }
}
