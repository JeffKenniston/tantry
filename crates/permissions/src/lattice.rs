use serde::{Deserialize, Serialize};

/// Represents the evaluation mode in the permission join-semilattice.
/// Forms a partial order where Allow < Interrupt < Deny.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PermissionMode {
    /// Action is explicitly allowed.
    Allow = 0,
    /// Action requires human-in-the-loop interrupt or explicit confirmation.
    Interrupt = 1,
    /// Action is explicitly denied.
    Deny = 2,
}

impl PermissionMode {
    /// Least Upper Bound / Join ($\sqcup$)
    /// Computes the supremum in the join-semilattice.
    pub fn join(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }
}
