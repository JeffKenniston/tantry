use crate::ext::SpiffeId;
use crate::lattice::PermissionMode;
use bitflags::bitflags;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct FsOperation: u8 {
        const READ   = 0b0001;
        const WRITE  = 0b0010;
        const DELETE = 0b0100;
        const EXEC   = 0b1000;
        const ALL    = 0b1111;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsPolicyRule {
    pub glob_pattern: String,
    pub operations: FsOperation,
    pub mode: PermissionMode,
    pub required_spiffe_prefix: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CompiledFsAutomaton {
    pub default_mode: PermissionMode,
    pub rules: Vec<FsPolicyRule>,
    glob_set: GlobSet,
}

impl CompiledFsAutomaton {
    pub fn new(
        default_mode: PermissionMode,
        rules: Vec<FsPolicyRule>,
    ) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for rule in &rules {
            let glob = Glob::new(&rule.glob_pattern)?;
            builder.add(glob);
        }
        let glob_set = builder.build()?;

        Ok(Self {
            default_mode,
            rules,
            glob_set,
        })
    }

    pub fn evaluate(&self, svid: &SpiffeId, op: FsOperation, raw_path: &str) -> PermissionMode {
        let normalized_path = match base::path::validate_and_normalize_path(raw_path) {
            Ok(p) => p,
            Err(_) => return PermissionMode::Deny,
        };

        let matches = self.glob_set.matches(&normalized_path);
        if matches.is_empty() {
            return self.default_mode;
        }

        let mut final_mode: Option<PermissionMode> = None;

        for rule_idx in matches {
            let rule = &self.rules[rule_idx];
            if !rule.operations.contains(op) {
                continue;
            }

            let prefix_matches = match &rule.required_spiffe_prefix {
                Some(pfx) => svid.uri().starts_with(pfx),
                None => true,
            };

            if prefix_matches {
                let m = rule.mode;
                final_mode = Some(match final_mode {
                    None => m,
                    Some(existing) => existing.join(m),
                });
            }
        }

        final_mode.unwrap_or(self.default_mode)
    }
}
