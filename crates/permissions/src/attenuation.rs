use crate::capabilities::{EnvCapability, FsCapability, McpCapability, NetCapability};
use crate::lattice::PermissionMode;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct PermissionLattice {
    pub fs: FsCapability,
    pub net: NetCapability,
    pub env: EnvCapability,
    pub mcp: McpCapability,
    pub interrupt_on_tools: BTreeMap<String, PermissionMode>,
}

impl PermissionLattice {
    pub fn narrow_for_subagent(
        &self,
        child_requested: &PermissionLattice,
    ) -> Result<PermissionLattice, globset::Error> {
        let mut effective_fs = child_requested.fs.clone();
        effective_fs.set_parent(Arc::new(self.fs.automaton.clone()));

        let mut effective_net = child_requested.net.clone();
        effective_net.set_parent(Arc::new(self.net.clone()));

        let mut effective_env = child_requested.env.clone();
        effective_env.set_parent(Arc::new(self.env.clone()));

        let mut effective_mcp = child_requested.mcp.clone();
        effective_mcp.max_spend_micros = std::cmp::min(
            self.mcp.max_spend_micros,
            child_requested.mcp.max_spend_micros,
        );
        effective_mcp.set_parent(Arc::new(self.mcp.clone()));

        let mut effective_interrupt = self.interrupt_on_tools.clone();
        for (tool, mode) in &child_requested.interrupt_on_tools {
            let existing = effective_interrupt
                .get(tool)
                .copied()
                .unwrap_or(PermissionMode::Allow);
            effective_interrupt.insert(tool.clone(), existing.join(*mode));
        }

        Ok(PermissionLattice {
            fs: effective_fs,
            net: effective_net,
            env: effective_env,
            mcp: effective_mcp,
            interrupt_on_tools: effective_interrupt,
        })
    }
}
