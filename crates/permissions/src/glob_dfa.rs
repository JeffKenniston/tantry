use crate::ext::SpiffeId;
use crate::lattice::PermissionMode;
use bitflags::bitflags;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

bitflags! {
    /// Filesystem operations covered by policy rules.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct FsOperation: u8 {
        /// Read operation.
        const READ   = 0b0001;
        /// Write operation.
        const WRITE  = 0b0010;
        /// Delete operation.
        const DELETE = 0b0100;
        /// Execute operation.
        const EXEC   = 0b1000;
        /// All operations.
        const ALL    = 0b1111;
    }
}

/// A policy rule defining a glob pattern and associated filesystem operations and evaluation mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsPolicyRule {
    /// The glob pattern to match against.
    pub glob_pattern: String,
    /// The filesystem operations this rule applies to.
    pub operations: FsOperation,
    /// The evaluation mode (Allow, Interrupt, or Deny).
    pub mode: PermissionMode,
    /// The optional SPIFFE prefix required for this rule to apply.
    pub required_spiffe_prefix: Option<String>,
}

/// A compiled automaton for evaluating filesystem policies using a `GlobSet`.
#[derive(Debug, Clone)]
pub struct CompiledFsAutomaton {
    /// The default mode to return if no rules match.
    pub default_mode: PermissionMode,
    /// The list of policy rules.
    pub rules: Vec<FsPolicyRule>,
    glob_set: GlobSet,
}

impl CompiledFsAutomaton {
    /// Creates a new `CompiledFsAutomaton` from the given default mode and policy rules.
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

    /// Evaluates the given operation and path against the rules, returning the resulting `PermissionMode`.
    pub fn evaluate(&self, svid: &SpiffeId, op: FsOperation, raw_path: &str) -> PermissionMode {
        let normalized_path = match base::path::validate_and_normalize_path(raw_path) {
            Ok(p) => p,
            Err(_) => return PermissionMode::Deny,
        };

        let matches = self.glob_set.matches(&normalized_path);
        let my_mode = if matches.is_empty() {
            self.default_mode
        } else {
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
        };

        my_mode
    }
}
