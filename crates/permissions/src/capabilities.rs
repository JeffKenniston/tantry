use crate::ext::{ScopedTunnelRegistry, SpiffeId};
use crate::glob_dfa::{CompiledFsAutomaton, FsOperation};
use crate::lattice::PermissionMode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct FsCapability {
    pub automaton: CompiledFsAutomaton,
}

impl FsCapability {
    pub fn new(automaton: CompiledFsAutomaton) -> Self {
        Self { automaton }
    }

    pub fn evaluate(&self, svid: &SpiffeId, op: FsOperation, raw_path: &str) -> PermissionMode {
        self.automaton.evaluate(svid, op, raw_path)
    }
}

use globset::{Glob, GlobSet, GlobSetBuilder};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetPolicyRule {
    pub domain_glob: String,
    pub allowed_ports: Vec<(u16, u16)>,
    pub allowed_methods: Vec<String>,
    pub mode: PermissionMode,
}

#[derive(Debug, Clone)]
pub struct NetCapability {
    pub default_mode: PermissionMode,
    pub rules: Vec<NetPolicyRule>,
    glob_set: GlobSet,
}

impl NetCapability {
    pub fn new(default_mode: PermissionMode, rules: Vec<NetPolicyRule>) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for rule in &rules {
            builder.add(Glob::new(&rule.domain_glob)?);
        }
        let glob_set = builder.build()?;

        Ok(Self {
            default_mode,
            rules,
            glob_set,
        })
    }

    pub fn evaluate_egress(
        &self,
        host: &str,
        port: u16,
        method: Option<&str>,
        tunnel_registry: Option<&ScopedTunnelRegistry>,
        now_ms: i64,
    ) -> PermissionMode {
        let matches = self.glob_set.matches(host);

        let mut host_has_deny = false;
        let mut final_mode: Option<PermissionMode> = None;

        for &rule_idx in &matches {
            let rule = &self.rules[rule_idx];
            if rule.mode == PermissionMode::Deny {
                host_has_deny = true;
            }

            let port_match = rule.allowed_ports.is_empty()
                || rule.allowed_ports.iter().any(|&(start, end)| port >= start && port <= end);

            let method_match = rule.allowed_methods.is_empty()
                || match method {
                    Some(m) => rule.allowed_methods.iter().any(|allowed| allowed.eq_ignore_ascii_case(m)),
                    None => true,
                };

            if port_match && method_match {
                let m = rule.mode;
                final_mode = Some(match final_mode {
                    None => m,
                    Some(existing) => existing.join(m),
                });
            }
        }

        if tunnel_registry.map_or(false, |r| r.is_service_active(host, now_ms)) {
            if host_has_deny {
                return PermissionMode::Deny;
            } else {
                return PermissionMode::Allow;
            }
        }

        if matches.is_empty() {
            self.default_mode
        } else {
            final_mode.unwrap_or(self.default_mode)
        }
    }
}

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct EnvCapability {
    pub allow_globs: GlobSet,
    pub exact_allow_overrides: Vec<String>,
    secret_deny_globset: GlobSet,
}

impl EnvCapability {
    pub fn new(allow_globs: Vec<String>, exact_allow_overrides: Vec<String>) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for glob in &allow_globs {
            builder.add(Glob::new(glob)?);
        }
        let allow_globset = builder.build()?;

        let secrets = ["*KEY*", "*TOKEN*", "*SECRET*", "*PASSWORD*", "*CREDENTIAL*", "*PRIVATE*", "*BEARER*"];
        let mut secret_builder = GlobSetBuilder::new();
        for secret in secrets {
            secret_builder.add(Glob::new(secret)?);
        }
        let secret_deny_globset = secret_builder.build()?;

        Ok(Self {
            allow_globs: allow_globset,
            exact_allow_overrides,
            secret_deny_globset,
        })
    }

    pub fn scrub_host_env<I>(&self, host_vars: I) -> BTreeMap<String, String>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut env = BTreeMap::new();
        for (k, v) in host_vars {
            let is_exact_override = self.exact_allow_overrides.iter().any(|allowed| allowed.eq_ignore_ascii_case(&k));

            if is_exact_override {
                env.insert(k, v);
                continue;
            }

            let uppercase_k = k.to_uppercase();
            if self.secret_deny_globset.is_match(&uppercase_k) {
                continue;
            }

            if self.allow_globs.is_match(&k) {
                env.insert(k, v);
            }
        }
        env
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPolicyRule {
    pub server_tool_glob: String,
    pub max_spend_micros_per_call: u64,
    pub mode: PermissionMode,
}

#[derive(Debug, Clone)]
pub struct McpCapability {
    pub default_mode: PermissionMode,
    pub effective_max_spend_micros: u64,
    pub rules: Vec<McpPolicyRule>,
    glob_set: GlobSet,
}

impl McpCapability {
    pub fn new(
        default_mode: PermissionMode,
        effective_max_spend_micros: u64,
        rules: Vec<McpPolicyRule>,
    ) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for rule in &rules {
            builder.add(Glob::new(&rule.server_tool_glob)?);
        }
        let glob_set = builder.build()?;

        Ok(Self {
            default_mode,
            effective_max_spend_micros,
            rules,
            glob_set,
        })
    }

    pub fn evaluate_mcp_call(
        &self,
        server_name: &str,
        tool_name: &str,
        estimated_spend_micros: u64,
    ) -> PermissionMode {
        if estimated_spend_micros > self.effective_max_spend_micros {
            return PermissionMode::Deny;
        }

        let query = format!("{}:{}", server_name, tool_name);
        let matches = self.glob_set.matches(&query);

        if matches.is_empty() {
            return self.default_mode;
        }

        let mut final_mode: Option<PermissionMode> = None;

        for &rule_idx in &matches {
            let rule = &self.rules[rule_idx];
            let m = rule.mode;
            final_mode = Some(match final_mode {
                None => m,
                Some(existing) => existing.join(m),
            });
        }

        final_mode.unwrap_or(self.default_mode)
    }
}
