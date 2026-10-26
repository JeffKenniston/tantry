use crate::glob_dfa::{CompiledFsAutomaton, FsOperation};
use crate::lattice::PermissionMode;
use globset::{Glob, GlobSet, GlobSetBuilder};
use iam::spiffe::SpiffeId;
use iam::ScopedTunnelRegistry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Represents a filesystem capability.
#[derive(Debug, Clone)]
pub enum FsCapability {
    /// A base capability wrapping a compiled automaton.
    Base(Arc<CompiledFsAutomaton>),
    /// A composite capability combining parent and child.
    Composite {
        /// Parent capability.
        parent: Arc<FsCapability>,
        /// Child capability.
        child: Arc<FsCapability>,
    },
}

impl FsCapability {
    /// Evaluates the filesystem operation pointwise.
    pub fn evaluate(&self, svid: &SpiffeId, op: FsOperation, raw_path: &str) -> PermissionMode {
        match self {
            Self::Base(automaton) => automaton.evaluate(svid, op, raw_path),
            Self::Composite { parent, child } => parent
                .evaluate(svid, op, raw_path)
                .join(child.evaluate(svid, op, raw_path)),
        }
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

/// Network automaton.
#[derive(Debug, Clone)]
pub struct NetAutomaton {
    /// Default evaluation mode.
    pub default_mode: PermissionMode,
    /// Network rules.
    pub rules: Vec<NetPolicyRule>,
    /// Precompiled glob set.
    pub glob_set: GlobSet,
}

/// Represents a network capability.
#[derive(Debug, Clone)]
pub enum NetCapability {
    /// A base network capability.
    Base(Arc<NetAutomaton>),
    /// A composite capability.
    Composite {
        /// Parent capability.
        parent: Arc<NetCapability>,
        /// Child capability.
        child: Arc<NetCapability>,
    },
}

impl NetCapability {
    /// Creates a new network capability from rules.
    pub fn new(
        default_mode: PermissionMode,
        rules: Vec<NetPolicyRule>,
    ) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for rule in &rules {
            builder.add(Glob::new(&rule.domain_glob)?);
        }
        let glob_set = builder.build()?;

        Ok(Self::Base(Arc::new(NetAutomaton {
            default_mode,
            rules,
            glob_set,
        })))
    }

    /// Evaluates network egress constraints pointwise.
    pub fn evaluate_egress(
        &self,
        host: &str,
        port: u16,
        method: Option<&str>,
        tunnel_registry: Option<&ScopedTunnelRegistry>,
        now_ms: i64,
    ) -> PermissionMode {
        match self {
            Self::Base(automaton) => {
                let matches = automaton.glob_set.matches(host);
                let mut host_has_deny = false;
                let mut final_mode: Option<PermissionMode> = None;

                for &rule_idx in &matches {
                    let rule = &automaton.rules[rule_idx];
                    if rule.mode == PermissionMode::Deny {
                        host_has_deny = true;
                    }

                    let port_match = rule.allowed_ports.is_empty()
                        || rule
                            .allowed_ports
                            .iter()
                            .any(|&(start, end)| port >= start && port <= end);

                    let method_match = rule.allowed_methods.is_empty()
                        || match method {
                            Some(m) => rule
                                .allowed_methods
                                .iter()
                                .any(|allowed| allowed.eq_ignore_ascii_case(m)),
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

                if tunnel_registry.is_some_and(|r| r.is_service_active(host, now_ms)) {
                    if host_has_deny {
                        return PermissionMode::Deny;
                    } else {
                        return PermissionMode::Allow;
                    }
                }

                if matches.is_empty() {
                    automaton.default_mode
                } else {
                    final_mode.unwrap_or(automaton.default_mode)
                }
            }
            Self::Composite { parent, child } => parent
                .evaluate_egress(host, port, method, tunnel_registry, now_ms)
                .join(child.evaluate_egress(host, port, method, tunnel_registry, now_ms)),
        }
    }
}

/// Environment automaton.
#[derive(Debug, Clone)]
pub struct EnvAutomaton {
    /// Globs for allowed variables.
    pub allow_globs: GlobSet,
    /// Exact names for allowed overrides.
    pub exact_allow_overrides: Vec<String>,
    /// Globs for denying secret variables.
    pub secret_deny_globset: GlobSet,
}

/// Represents an environment capability.
#[derive(Debug, Clone)]
pub enum EnvCapability {
    /// A base environment capability.
    Base(Arc<EnvAutomaton>),
    /// A composite environment capability.
    Composite {
        /// Parent capability.
        parent: Arc<EnvCapability>,
        /// Child capability.
        child: Arc<EnvCapability>,
    },
}

impl EnvCapability {
    /// Creates a new base environment capability.
    pub fn new(
        allow_globs: Vec<String>,
        exact_allow_overrides: Vec<String>,
    ) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for glob in &allow_globs {
            builder.add(Glob::new(glob)?);
        }
        let allow_globset = builder.build()?;

        let secrets = [
            "*KEY*",
            "*TOKEN*",
            "*SECRET*",
            "*PASSWORD*",
            "*CREDENTIAL*",
            "*PRIVATE*",
            "*BEARER*",
        ];
        let mut secret_builder = GlobSetBuilder::new();
        for secret in secrets {
            secret_builder.add(Glob::new(secret)?);
        }
        let secret_deny_globset = secret_builder.build()?;

        Ok(Self::Base(Arc::new(EnvAutomaton {
            allow_globs: allow_globset,
            exact_allow_overrides,
            secret_deny_globset,
        })))
    }

    /// Scrubs host environment variables. For composites, variables must be allowed by both.
    pub fn scrub_host_env<I>(&self, host_vars: I) -> BTreeMap<String, String>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        match self {
            Self::Base(automaton) => {
                let mut env = BTreeMap::new();
                for (k, v) in host_vars {
                    let is_exact_override = automaton
                        .exact_allow_overrides
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(&k));

                    if is_exact_override {
                        env.insert(k, v);
                        continue;
                    }

                    let uppercase_k = k.to_uppercase();
                    if automaton.secret_deny_globset.is_match(&uppercase_k) {
                        continue;
                    }

                    if automaton.allow_globs.is_match(&k) {
                        env.insert(k, v);
                    }
                }
                env
            }
            Self::Composite { parent, child } => {
                let host_vars: Vec<(String, String)> = host_vars.into_iter().collect();
                let p_env = parent.scrub_host_env(host_vars.clone());
                let c_env = child.scrub_host_env(host_vars);

                let mut final_env = BTreeMap::new();
                for (k, v) in p_env {
                    if c_env.contains_key(&k) {
                        final_env.insert(k, v);
                    }
                }
                final_env
            }
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

/// MCP automaton.
#[derive(Debug, Clone)]
pub struct McpAutomaton {
    /// Default evaluation mode.
    pub default_mode: PermissionMode,
    /// Rules.
    pub rules: Vec<McpPolicyRule>,
    /// Precompiled glob set.
    pub glob_set: GlobSet,
}

/// Represents an MCP capability.
#[derive(Debug, Clone)]
pub enum McpCapability {
    /// A base MCP capability.
    Base {
        /// Base max spend micros.
        max_spend_micros: u64,
        /// Effective max spend micros.
        effective_max_spend_micros: u64,
        /// Automaton.
        automaton: Arc<McpAutomaton>,
    },
    /// A composite MCP capability.
    Composite {
        /// Parent capability.
        parent: Arc<McpCapability>,
        /// Child capability.
        child: Arc<McpCapability>,
        /// Max spend micros.
        max_spend_micros: u64,
        /// Effective max spend micros.
        effective_max_spend_micros: u64,
    },
}

impl McpCapability {
    /// Returns the maximum spend in microseconds.
    pub fn max_spend_micros(&self) -> u64 {
        match self {
            Self::Base {
                max_spend_micros, ..
            } => *max_spend_micros,
            Self::Composite {
                max_spend_micros, ..
            } => *max_spend_micros,
        }
    }

    /// Creates a new MCP capability.
    pub fn new(
        default_mode: PermissionMode,
        max_spend_micros: u64,
        effective_max_spend_micros: u64,
        rules: Vec<McpPolicyRule>,
    ) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for rule in &rules {
            builder.add(Glob::new(&rule.server_tool_glob)?);
        }
        let glob_set = builder.build()?;

        Ok(Self::Base {
            max_spend_micros,
            effective_max_spend_micros,
            automaton: Arc::new(McpAutomaton {
                default_mode,
                rules,
                glob_set,
            }),
        })
    }

    /// Evaluates an MCP call pointwise.
    pub fn evaluate_mcp_call(
        &self,
        server_name: &str,
        tool_name: &str,
        estimated_spend_micros: u64,
    ) -> PermissionMode {
        match self {
            Self::Base {
                effective_max_spend_micros,
                automaton,
                ..
            } => {
                if estimated_spend_micros > *effective_max_spend_micros {
                    return PermissionMode::Deny;
                }

                let query = format!("{}:{}", server_name, tool_name);
                let matches = automaton.glob_set.matches(&query);

                if matches.is_empty() {
                    return automaton.default_mode;
                }

                let mut final_mode: Option<PermissionMode> = None;

                for &rule_idx in &matches {
                    let rule = &automaton.rules[rule_idx];
                    let m = rule.mode;
                    final_mode = Some(match final_mode {
                        None => m,
                        Some(existing) => existing.join(m),
                    });
                }

                final_mode.unwrap_or(automaton.default_mode)
            }
            Self::Composite {
                parent,
                child,
                effective_max_spend_micros,
                ..
            } => {
                if estimated_spend_micros > *effective_max_spend_micros {
                    return PermissionMode::Deny;
                }
                parent
                    .evaluate_mcp_call(server_name, tool_name, estimated_spend_micros)
                    .join(child.evaluate_mcp_call(server_name, tool_name, estimated_spend_micros))
            }
        }
    }
}
