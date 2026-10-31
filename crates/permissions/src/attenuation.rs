use crate::capabilities::{EnvCapability, FsCapability, McpCapability, NetCapability};
use crate::lattice::PermissionMode;
use std::collections::BTreeMap;

/// Represents a 4-dimensional permission lattice.
#[derive(Debug, Clone)]
pub struct PermissionLattice {
    /// Filesystem capability.
    pub fs: FsCapability,
    /// Network capability.
    pub net: NetCapability,
    /// Environment capability.
    pub env: EnvCapability,
    /// MCP capability.
    pub mcp: McpCapability,
    /// Specific tools to interrupt on.
    pub interrupt_on_tools: BTreeMap<String, PermissionMode>,
}

impl PermissionLattice {
    /// Constructs a composite lattice where every evaluation query computes the pointwise least upper bound.
    /// This enforces the pointwise join attenuation law $\text{Effective}(x) = \mathcal{P}_{\text{parent}}(x) \sqcup \mathcal{C}_{\text{child}}(x)$.
    pub fn narrow_for_subagent(&self, child: &PermissionLattice) -> PermissionLattice {
        let mut new_interrupt = self.interrupt_on_tools.clone();
        for (k, v) in &child.interrupt_on_tools {
            new_interrupt
                .entry(k.clone())
                .and_modify(|existing| *existing = existing.join(*v))
                .or_insert(*v);
        }

        PermissionLattice {
            fs: self.fs.narrow(&child.fs),
            net: self.net.narrow(&child.net),
            env: self.env.narrow(&child.env),
            mcp: self.mcp.narrow(&child.mcp),
            interrupt_on_tools: new_interrupt,
        }
    }
}
