use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PermissionMode {
    Allow = 0,
    Interrupt = 1,
    Deny = 2,
}

impl PermissionMode {
    pub const BOTTOM: Self = Self::Allow;
    pub const TOP: Self = Self::Deny;

    #[inline]
    pub fn join(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }
}
