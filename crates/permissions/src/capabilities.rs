use crate::glob_dfa::{CompiledFsAutomaton, FsOperation, FsPolicyRule};
use crate::lattice::PermissionMode;
use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use iam::spiffe::SpiffeId;
use iam::ScopedTunnelRegistry;
use serde::{Deserialize, Serialize};

/// Represents a filesystem capability.
#[derive(Debug, Clone)]
pub struct FsCapability {
    pub layers: smallvec::SmallVec<[CompiledFsAutomaton; 2]>,
}

impl FsCapability {
    pub fn new(rules: Vec<FsPolicyRule>, default_mode: PermissionMode) -> Result<Self, globset::Error> {
        let automaton = CompiledFsAutomaton::compile(rules, default_mode)?;
        let mut layers = smallvec::SmallVec::new();
        layers.push(automaton);
        Ok(Self { layers })
    }

    pub fn evaluate(&self, svid: &SpiffeId, op: FsOperation, raw_path: &str) -> PermissionMode {
        let norm_path = match base::path::validate_and_normalize_path(raw_path) {
            Ok(p) => p,
            Err(_) => return PermissionMode::Deny,
        };

        if self.layers.is_empty() {
            return PermissionMode::Deny;
        }

        self.layers.iter().fold(PermissionMode::Allow, |acc, layer| {
            acc.join(layer.evaluate_normalized(svid, op, &norm_path))
        })
    }

    pub fn narrow(&self, child: &FsCapability) -> FsCapability {
        let mut new_layers = self.layers.clone();
        new_layers.extend(child.layers.iter().cloned());
        FsCapability { layers: new_layers }
    }
}

/// Network policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetPolicyRule {
    /// Domain glob pattern.
    pub domain_glob: String,
    /// Allowed ports.
    pub allowed_ports: Vec<(u16, u16)>,
    /// Allowed HTTP methods.
    pub allowed_methods: Vec<String>,
    /// Evaluation mode.
    pub mode: PermissionMode,
}

#[derive(Debug, Clone)]
pub struct CompiledNetLayer {
    pub glob_set: GlobSet,
    pub rules: Vec<NetPolicyRule>,
    pub default_mode: PermissionMode,
}

impl CompiledNetLayer {
    pub fn compile(rules: Vec<NetPolicyRule>, default_mode: PermissionMode) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for rule in &rules {
            builder.add(Glob::new(&rule.domain_glob)?);
        }
        let glob_set = builder.build()?;
        Ok(Self {
            glob_set,
            rules,
            default_mode,
        })
    }

    pub fn evaluate_target(&self, norm_host: &str, port: u16, method: Option<&str>) -> (PermissionMode, bool) {
        let matches = self.glob_set.matches(norm_host);

        let mut has_explicit_deny = false;
        let mut has_matches = false;

        let final_mode = matches.into_iter().filter_map(|rule_idx| {
            let rule = &self.rules[rule_idx];

            let port_match = rule.allowed_ports.is_empty()
                || rule.allowed_ports.iter().any(|&(start, end)| port >= start && port <= end);

            let method_match = rule.allowed_methods.is_empty()
                || method.map_or(false, |m| rule.allowed_methods.iter().any(|allowed| allowed.eq_ignore_ascii_case(m)));

            if port_match && method_match {
                if rule.mode == PermissionMode::Deny {
                    has_explicit_deny = true;
                }
                Some(rule.mode)
            } else {
                None
            }
        }).fold(PermissionMode::Allow, |acc, mode| {
            has_matches = true;
            acc.join(mode)
        });

        if !has_matches {
            (self.default_mode, false)
        } else {
            (final_mode, has_explicit_deny)
        }
    }
}

/// Represents a network capability.
#[derive(Debug, Clone)]
pub struct NetCapability {
    pub layers: smallvec::SmallVec<[CompiledNetLayer; 2]>,
}

impl NetCapability {
    pub fn new(
        default_mode: PermissionMode,
        rules: Vec<NetPolicyRule>,
    ) -> Result<Self, globset::Error> {
        let layer = CompiledNetLayer::compile(rules, default_mode)?;
        let mut layers = smallvec::SmallVec::new();
        layers.push(layer);
        Ok(Self { layers })
    }

    pub fn evaluate_egress(
        &self,
        host: &str,
        port: u16,
        method: Option<&str>,
        tunnel_registry: Option<&ScopedTunnelRegistry>,
        now_ms: i64,
    ) -> PermissionMode {
        let norm_host = host.trim().to_lowercase();
        let norm_host = norm_host.strip_suffix('.').unwrap_or(norm_host.as_str());

        if norm_host.is_empty() || norm_host.contains('/') || norm_host.contains('\\') || norm_host.contains(|c: char| c.is_whitespace() || c.is_ascii_control()) {
            return PermissionMode::Deny;
        }

        let mut layer_modes = smallvec::SmallVec::<[PermissionMode; 2]>::new();
        for layer in &self.layers {
            let (mode, has_explicit_deny) = layer.evaluate_target(norm_host, port, method);
            if has_explicit_deny {
                return PermissionMode::Deny;
            }
            layer_modes.push(mode);
        }

        if tunnel_registry.is_some_and(|r| r.is_service_active(norm_host, now_ms)) {
            return PermissionMode::Allow;
        }

        layer_modes.into_iter().fold(PermissionMode::Allow, |acc, mode| acc.join(mode))
    }

    pub fn narrow(&self, child: &NetCapability) -> NetCapability {
        let mut new_layers = self.layers.clone();
        new_layers.extend(child.layers.iter().cloned());
        NetCapability { layers: new_layers }
    }
}

pub const MANDATORY_SECRET_DENY_PATTERNS: &[&str] = &[
    "*KEY*",
    "*TOKEN*",
    "*SECRET*",
    "*PASSWORD*",
    "*CREDENTIAL*",
    "*PRIVATE*",
    "*BEARER*",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPolicyRule {
    pub var_glob: String,
    pub mode: PermissionMode,
}

#[derive(Debug, Clone)]
pub struct CompiledEnvLayer {
    pub glob_set: GlobSet,
    pub rules: Vec<EnvPolicyRule>,
    pub default_mode: PermissionMode,
}

/// Represents an environment capability.
#[derive(Debug, Clone)]
pub struct EnvCapability {
    pub secret_deny_globset: GlobSet,
    pub explicit_secret_allowlist: std::collections::BTreeSet<String>,
    pub layers: smallvec::SmallVec<[CompiledEnvLayer; 2]>,
}

impl EnvCapability {
    pub fn compile(
        rules: Vec<EnvPolicyRule>,
        explicit_secret_allowlist: std::collections::BTreeSet<String>,
        default_mode: PermissionMode,
    ) -> Result<Self, globset::Error> {
        let mut secret_builder = GlobSetBuilder::new();
        for &pat in MANDATORY_SECRET_DENY_PATTERNS {
            secret_builder.add(GlobBuilder::new(pat).case_insensitive(true).build()?);
        }
        let secret_deny_globset = secret_builder.build()?;

        let mut builder = GlobSetBuilder::new();
        for rule in &rules {
            builder.add(Glob::new(&rule.var_glob)?);
        }
        let glob_set = builder.build()?;

        let layer = CompiledEnvLayer {
            glob_set,
            rules,
            default_mode,
        };

        let mut layers = smallvec::SmallVec::new();
        layers.push(layer);

        Ok(Self {
            secret_deny_globset,
            explicit_secret_allowlist,
            layers,
        })
    }

    pub fn evaluate_var(&self, var_name: &str) -> PermissionMode {
        if var_name.is_empty() {
            return PermissionMode::Deny;
        }

        if self.secret_deny_globset.is_match(var_name) {
            if !self.explicit_secret_allowlist.contains(var_name) {
                return PermissionMode::Deny;
            }
        }

        self.layers.iter().fold(PermissionMode::Allow, |acc, layer| {
            let matches = layer.glob_set.matches(var_name);
            let layer_mode = if matches.is_empty() {
                layer.default_mode
            } else {
                matches.into_iter().map(|idx| layer.rules[idx].mode).fold(PermissionMode::Allow, |acc_rule, mode| acc_rule.join(mode))
            };
            acc.join(layer_mode)
        })
    }

    pub fn scrub_host_env<I, K, V>(&self, host_vars: I) -> std::collections::BTreeMap<String, String>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: Into<String>,
    {
        host_vars
            .into_iter()
            .filter(|(k, _)| self.evaluate_var(k.as_ref()) == PermissionMode::Allow)
            .map(|(k, v)| (k.as_ref().to_owned(), v.into()))
            .collect()
    }

    pub fn narrow(&self, child: &EnvCapability) -> EnvCapability {
        let mut layers = self.layers.clone();
        layers.extend(child.layers.iter().cloned());
        let explicit_secret_allowlist = self
            .explicit_secret_allowlist
            .intersection(&child.explicit_secret_allowlist)
            .cloned()
            .collect();
        EnvCapability {
            secret_deny_globset: self.secret_deny_globset.clone(),
            explicit_secret_allowlist,
            layers,
        }
    }
}

/// MCP policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPolicyRule {
    /// Glob for server:tool name.
    pub server_tool_glob: String,
    /// Max spend per call.
    pub max_spend_micros_per_call: u64,
    /// Evaluation mode.
    pub mode: PermissionMode,
}

#[derive(Debug, Clone)]
pub struct CompiledMcpLayer {
    pub glob_set: GlobSet,
    pub rules: Vec<McpPolicyRule>,
    pub default_mode: PermissionMode,
}

/// Represents an MCP capability.
#[derive(Debug, Clone)]
pub struct McpCapability {
    pub layers: smallvec::SmallVec<[CompiledMcpLayer; 2]>,
    pub effective_max_spend_micros_per_call: u64,
}

impl McpCapability {
    pub fn new(
        default_mode: PermissionMode,
        effective_max_spend_micros_per_call: u64,
        rules: Vec<McpPolicyRule>,
    ) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for rule in &rules {
            builder.add(Glob::new(&rule.server_tool_glob)?);
        }
        let glob_set = builder.build()?;

        let layer = CompiledMcpLayer {
            glob_set,
            rules,
            default_mode,
        };

        let mut layers = smallvec::SmallVec::new();
        layers.push(layer);

        Ok(Self {
            layers,
            effective_max_spend_micros_per_call,
        })
    }

    pub fn evaluate_call(
        &self,
        server_name: &str,
        tool_name: &str,
        estimated_spend_micros: u64,
    ) -> PermissionMode {
        if estimated_spend_micros > self.effective_max_spend_micros_per_call {
            return PermissionMode::Deny;
        }
        let call_target = format!("{server_name}:{tool_name}");
        self.layers.iter().fold(PermissionMode::Allow, |acc, layer| {
            let matches = layer.glob_set.matches(&call_target);
            let layer_mode = if matches.is_empty() {
                layer.default_mode
            } else {
                matches.into_iter().map(|idx| layer.rules[idx].mode).fold(PermissionMode::Allow, |acc_rule, mode| acc_rule.join(mode))
            };
            acc.join(layer_mode)
        })
    }

    pub fn narrow(&self, child: &McpCapability) -> McpCapability {
        let mut layers = self.layers.clone();
        layers.extend(child.layers.iter().cloned());
        McpCapability {
            layers,
            effective_max_spend_micros_per_call: self
                .effective_max_spend_micros_per_call
                .min(child.effective_max_spend_micros_per_call),
        }
    }
}
