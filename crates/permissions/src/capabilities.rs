use crate::ext::ScopedTunnelRegistry;
use crate::glob_dfa::CompiledFsAutomaton;
use crate::lattice::PermissionMode;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct FsCapability {
    pub automaton: CompiledFsAutomaton,
}

impl FsCapability {
    pub fn set_parent(&mut self, p: Arc<CompiledFsAutomaton>) {
        self.automaton.set_parent(p);
    }
}

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
    domain_glob_set: GlobSet,
    parent: Option<Arc<NetCapability>>,
}

impl NetCapability {
    pub fn new(
        default_mode: PermissionMode,
        rules: Vec<NetPolicyRule>,
    ) -> Result<Self, globset::Error> {
        Self::new_with_parent(default_mode, rules, None)
    }

    pub fn new_with_parent(
        default_mode: PermissionMode,
        rules: Vec<NetPolicyRule>,
        parent: Option<Arc<NetCapability>>,
    ) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for rule in &rules {
            builder.add(Glob::new(&rule.domain_glob)?);
        }
        let domain_glob_set = builder.build()?;

        Ok(Self {
            default_mode,
            rules,
            domain_glob_set,
            parent,
        })
    }

    pub fn set_parent(&mut self, p: Arc<NetCapability>) {
        self.parent = Some(p);
    }

    pub fn evaluate_egress(
        &self,
        host: &str,
        port: u16,
        method: Option<&str>,
        tunnel_registry: Option<&ScopedTunnelRegistry>,
        now_ms: i64,
    ) -> PermissionMode {
        let mut my_mode = None;

        if let Some(registry) = tunnel_registry {
            if registry.is_service_active(host, now_ms) {
                let matches = self.domain_glob_set.matches(host);
                let mut deny = false;
                for rule_idx in matches {
                    let rule = &self.rules[rule_idx];
                    if rule.mode == PermissionMode::Deny {
                        deny = true;
                        break;
                    }
                }
                if deny {
                    my_mode = Some(PermissionMode::Deny);
                } else {
                    my_mode = Some(PermissionMode::Allow);
                }
            }
        }

        let my_mode = my_mode.unwrap_or_else(|| {
            let matches = self.domain_glob_set.matches(host);
            if matches.is_empty() {
                return self.default_mode;
            }

            let mut final_mode: Option<PermissionMode> = None;

            for rule_idx in matches {
                let rule = &self.rules[rule_idx];

                let port_allowed = rule.allowed_ports.is_empty()
                    || rule
                        .allowed_ports
                        .iter()
                        .any(|&(start, end)| port >= start && port <= end);
                if !port_allowed {
                    continue;
                }

                let method_allowed = match method {
                    Some(m) => {
                        rule.allowed_methods.is_empty()
                            || rule
                                .allowed_methods
                                .iter()
                                .any(|allowed| allowed.eq_ignore_ascii_case(m))
                    }
                    None => true,
                };
                if !method_allowed {
                    continue;
                }

                let m = rule.mode;
                final_mode = Some(match final_mode {
                    None => m,
                    Some(existing) => existing.join(m),
                });
            }

            final_mode.unwrap_or(self.default_mode)
        });

        if let Some(p) = &self.parent {
            let parent_mode = p.evaluate_egress(host, port, method, tunnel_registry, now_ms);
            my_mode.join(parent_mode)
        } else {
            my_mode
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnvCapability {
    pub exact_match_allow: Vec<String>,
    pub allow_globs: GlobSet,
    secret_deny_globset: GlobSet,
    parent: Option<Arc<EnvCapability>>,
}

impl EnvCapability {
    pub fn new(
        allow_globs: Vec<String>,
        exact_match_allow: Vec<String>,
    ) -> Result<Self, globset::Error> {
        Self::new_with_parent(allow_globs, exact_match_allow, None)
    }

    pub fn set_parent(&mut self, p: Arc<EnvCapability>) {
        self.parent = Some(p);
    }

    pub fn new_with_parent(
        allow_globs: Vec<String>,
        exact_match_allow: Vec<String>,
        parent: Option<Arc<EnvCapability>>,
    ) -> Result<Self, globset::Error> {
        let mut allow_builder = GlobSetBuilder::new();
        for glob in &allow_globs {
            allow_builder.add(Glob::new(glob)?);
        }
        let allow_globs_set = allow_builder.build()?;

        let mut secret_builder = GlobSetBuilder::new();
        let secrets = [
            "*KEY*",
            "*TOKEN*",
            "*SECRET*",
            "*PASSWORD*",
            "*CREDENTIAL*",
            "*PRIVATE*",
            "*BEARER*",
        ];
        for secret in secrets {
            secret_builder.add(Glob::new(&format!("(?i){}", secret))?);
        }
        let secret_deny_globset = secret_builder.build()?;

        Ok(Self {
            exact_match_allow,
            allow_globs: allow_globs_set,
            secret_deny_globset,
            parent,
        })
    }

    fn is_allowed(&self, key: &str) -> bool {
        if self.secret_deny_globset.is_match(key) {
            if self.exact_match_allow.iter().any(|exact| exact == key) {
                return self
                    .parent
                    .as_ref()
                    .map(|p| p.is_allowed(key))
                    .unwrap_or(true);
            }
            return false;
        }

        if self.exact_match_allow.iter().any(|exact| exact == key) || self.allow_globs.is_match(key)
        {
            return self
                .parent
                .as_ref()
                .map(|p| p.is_allowed(key))
                .unwrap_or(true);
        }
        false
    }

    pub fn scrub_host_env<I, K, V>(&self, host_vars: I) -> BTreeMap<String, String>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut result = BTreeMap::new();

        for (k, v) in host_vars {
            let key = k.as_ref();
            if self.is_allowed(key) {
                result.insert(key.to_string(), v.as_ref().to_string());
            }
        }

        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPolicyRule {
    pub server_tool_glob: String,
    pub mode: PermissionMode,
}

#[derive(Debug, Clone)]
pub struct McpCapability {
    pub default_mode: PermissionMode,
    pub max_spend_micros: u64,
    pub rules: Vec<McpPolicyRule>,
    tool_glob_set: GlobSet,
    parent: Option<Arc<McpCapability>>,
}

impl McpCapability {
    pub fn new(
        default_mode: PermissionMode,
        max_spend_micros: u64,
        rules: Vec<McpPolicyRule>,
    ) -> Result<Self, globset::Error> {
        Self::new_with_parent(default_mode, max_spend_micros, rules, None)
    }

    pub fn new_with_parent(
        default_mode: PermissionMode,
        max_spend_micros: u64,
        rules: Vec<McpPolicyRule>,
        parent: Option<Arc<McpCapability>>,
    ) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for rule in &rules {
            builder.add(Glob::new(&rule.server_tool_glob)?);
        }
        let tool_glob_set = builder.build()?;

        Ok(Self {
            default_mode,
            max_spend_micros,
            rules,
            tool_glob_set,
            parent,
        })
    }

    pub fn set_parent(&mut self, p: Arc<McpCapability>) {
        self.parent = Some(p);
    }

    pub fn evaluate_mcp_call(
        &self,
        server_name: &str,
        tool_name: &str,
        estimated_spend_micros: u64,
    ) -> PermissionMode {
        let my_mode = if estimated_spend_micros > self.max_spend_micros {
            PermissionMode::Deny
        } else {
            let query = format!("{}:{}", server_name, tool_name);
            let matches = self.tool_glob_set.matches(&query);

            if matches.is_empty() {
                self.default_mode
            } else {
                let mut final_mode: Option<PermissionMode> = None;

                for rule_idx in matches {
                    let rule = &self.rules[rule_idx];
                    let m = rule.mode;
                    final_mode = Some(match final_mode {
                        None => m,
                        Some(existing) => existing.join(m),
                    });
                }

                final_mode.unwrap_or(self.default_mode)
            }
        };

        if let Some(p) = &self.parent {
            let parent_mode = p.evaluate_mcp_call(server_name, tool_name, estimated_spend_micros);
            my_mode.join(parent_mode)
        } else {
            my_mode
        }
    }
}
