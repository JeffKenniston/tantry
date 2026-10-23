use std::collections::BTreeMap;
use std::sync::Arc;
use crate::capabilities::{FsCapability, NetCapability, EnvCapability, McpCapability};
use crate::lattice::PermissionMode;

#[derive(Debug, Clone)]
pub struct PermissionLattice {
    pub fs: FsCapability,
    pub net: NetCapability,
    pub env: EnvCapability,
    pub mcp: McpCapability,
    pub interrupt_on_tools: BTreeMap<String, PermissionMode>,
}

impl PermissionLattice {
    pub fn narrow_for_subagent(&self, child_requested: &PermissionLattice) -> PermissionLattice {
        let mut new_interrupt = self.interrupt_on_tools.clone();
        for (k, v) in &child_requested.interrupt_on_tools {
            new_interrupt
                .entry(k.clone())
                .and_modify(|existing| *existing = existing.join(*v))
                .or_insert(*v);
        }

        let effective_max = std::cmp::min(
            self.mcp.max_spend_micros(),
            child_requested.mcp.max_spend_micros(),
        );

        PermissionLattice {
            fs: FsCapability::Composite {
                parent: Arc::new(self.fs.clone()),
                child: Arc::new(child_requested.fs.clone()),
            },
            net: NetCapability::Composite {
                parent: Arc::new(self.net.clone()),
                child: Arc::new(child_requested.net.clone()),
            },
            env: EnvCapability::Composite {
                parent: Arc::new(self.env.clone()),
                child: Arc::new(child_requested.env.clone()),
            },
            mcp: McpCapability::Composite {
                parent: Arc::new(self.mcp.clone()),
                child: Arc::new(child_requested.mcp.clone()),
                max_spend_micros: effective_max,
                effective_max_spend_micros: effective_max,
            },
            interrupt_on_tools: new_interrupt,
        }
    }
}
