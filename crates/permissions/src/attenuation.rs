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
        let mut fs_rules = self.fs.automaton.rules.clone();
        fs_rules.extend(child_requested.fs.automaton.rules.clone());
        let effective_fs_default = self
            .fs
            .automaton
            .default_mode
            .join(child_requested.fs.automaton.default_mode);
        let effective_fs = FsCapability {
            automaton: crate::glob_dfa::CompiledFsAutomaton::new(effective_fs_default, fs_rules)?,
        };

        let mut net_rules = self.net.rules.clone();
        net_rules.extend(child_requested.net.rules.clone());
        let effective_net_default = self.net.default_mode.join(child_requested.net.default_mode);
        let effective_net = NetCapability::new(effective_net_default, net_rules)?;

        let mut effective_env = child_requested.env.clone();
        effective_env.set_parent(Arc::new(self.env.clone()));

        let mut mcp_rules = self.mcp.rules.clone();
        mcp_rules.extend(child_requested.mcp.rules.clone());
        let effective_mcp_default = self.mcp.default_mode.join(child_requested.mcp.default_mode);
        let effective_max_spend = std::cmp::min(
            self.mcp.max_spend_micros,
            child_requested.mcp.max_spend_micros,
        );
        let effective_mcp =
            McpCapability::new(effective_mcp_default, effective_max_spend, mcp_rules)?;

        let mut effective_interrupt = self.interrupt_on_tools.clone();
        for (tool, mode) in &child_requested.interrupt_on_tools {
            let existing = effective_interrupt
                .get(tool)
                .copied()
                .unwrap_or(PermissionMode::Allow); // If not present, default is allow? Wait, actually if not present, maybe it's not interrupted.
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
