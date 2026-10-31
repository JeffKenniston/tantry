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
    /// satisfying `Effective(x) = Parent(x).join(Child(x)) >= Parent(x)`.
    pub fn narrow_for_subagent(&self, child: &PermissionLattice) -> PermissionLattice {
        let fs = self.fs.narrow(&child.fs);
        let net = self.net.narrow(&child.net);
        let env = self.env.narrow(&child.env);
        let mcp = self.mcp.narrow(&child.mcp);

        let mut joined_tools = self.interrupt_on_tools.clone();
        for (tool, mode) in &child.interrupt_on_tools {
            joined_tools
                .entry(tool.clone())
                .and_modify(|m| *m = m.join(*mode))
                .or_insert(*mode);
        }

        PermissionLattice {
            fs,
            net,
            env,
            mcp,
            interrupt_on_tools: joined_tools,
        }
    }
}
