use crate::lattice::PermissionMode;
use bitflags::bitflags;
use globset::{GlobSet, GlobSetBuilder};
use iam::spiffe::SpiffeId;
use serde::{Deserialize, Serialize};

bitflags! {
    /// Filesystem operations covered by policy rules.
    #[repr(transparent)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn compile(rules: Vec<FsPolicyRule>, default_mode: PermissionMode) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for rule in &rules {
            let glob = globset::GlobBuilder::new(&rule.glob_pattern).literal_separator(false).build()?;
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

        self.evaluate_normalized(svid, op, &normalized_path)
    }

    pub fn evaluate_normalized(&self, svid: &SpiffeId, op: FsOperation, norm_path: &str) -> PermissionMode {
        let matches = self.glob_set.matches(norm_path);
        if matches.is_empty() {
            return self.default_mode;
        }

        let matching_rules = matches.into_iter().filter_map(|rule_idx| {
            let rule = &self.rules[rule_idx];
            if !rule.operations.contains(op) {
                return None;
            }

            let prefix_matches = match &rule.required_spiffe_prefix {
                Some(pfx) => svid.uri().starts_with(pfx),
                None => true,
            };

            if prefix_matches {
                Some(rule)
            } else {
                None
            }
        });

        let mut has_matches = false;
        let final_mode = matching_rules.fold(PermissionMode::Allow, |acc, rule| {
            has_matches = true;
            acc.join(rule.mode)
        });

        if has_matches {
            final_mode
        } else {
            self.default_mode
        }
    }
}
