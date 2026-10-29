use crate::error::ProfileError;
use base::ast::MediaKind;
use runtime::AgentMiddleware;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

pub fn parse_profile_key(key: &str) -> Result<(&str, Option<&str>), ProfileError> {
    if let Some((provider, model)) = key.split_once(':') {
        if provider.trim().is_empty() || model.trim().is_empty() {
            return Err(ProfileError::InvalidProfileKey(key.to_string()));
        }
        Ok((provider, Some(model)))
    } else {
        if key.trim().is_empty() {
            return Err(ProfileError::InvalidProfileKey(key.to_string()));
        }
        Ok((key, None))
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct HarnessProfileOverride {
    pub system_prompt_prefix: Option<String>,
    pub system_prompt_suffix: Option<String>,
    pub excluded_tools: BTreeSet<String>,
    pub excluded_middleware: BTreeSet<String>,
    pub tool_description_overrides: BTreeMap<String, String>,
    #[serde(skip)]
    pub extra_middleware: Vec<Arc<dyn AgentMiddleware>>,
    pub supported_media_kinds: Option<Vec<MediaKind>>,
    pub init_kwargs: BTreeMap<String, serde_json::Value>,
    pub context_window_tokens: Option<usize>,
    pub general_purpose_subagent: Option<Box<HarnessProfileOverride>>,
}

impl fmt::Debug for HarnessProfileOverride {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let middleware_names: Vec<&str> = self
            .extra_middleware
            .iter()
            .map(|m| m.name())
            .collect();
        f.debug_struct("HarnessProfileOverride")
            .field("system_prompt_prefix", &self.system_prompt_prefix)
            .field("system_prompt_suffix", &self.system_prompt_suffix)
            .field("excluded_tools", &self.excluded_tools)
            .field("excluded_middleware", &self.excluded_middleware)
            .field("tool_description_overrides", &self.tool_description_overrides)
            .field("extra_middleware", &middleware_names)
            .field("supported_media_kinds", &self.supported_media_kinds)
            .field("init_kwargs", &self.init_kwargs)
            .field("context_window_tokens", &self.context_window_tokens)
            .field("general_purpose_subagent", &self.general_purpose_subagent)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HarnessProfile {
    pub profile_key: String,
    pub system_prompt_prefix: Option<String>,
    pub system_prompt_suffix: Option<String>,
    pub excluded_tools: BTreeSet<String>,
    pub excluded_middleware: BTreeSet<String>,
    pub tool_description_overrides: BTreeMap<String, String>,
    #[serde(skip)]
    pub extra_middleware: Vec<Arc<dyn AgentMiddleware>>,
    pub supported_media_kinds: Option<Vec<MediaKind>>,
    pub init_kwargs: BTreeMap<String, serde_json::Value>,
    pub context_window_tokens: usize,
    pub general_purpose_subagent: Option<Box<HarnessProfileOverride>>,
}

impl fmt::Debug for HarnessProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let middleware_names: Vec<&str> = self
            .extra_middleware
            .iter()
            .map(|m| m.name())
            .collect();
        f.debug_struct("HarnessProfile")
            .field("profile_key", &self.profile_key)
            .field("system_prompt_prefix", &self.system_prompt_prefix)
            .field("system_prompt_suffix", &self.system_prompt_suffix)
            .field("excluded_tools", &self.excluded_tools)
            .field("excluded_middleware", &self.excluded_middleware)
            .field("tool_description_overrides", &self.tool_description_overrides)
            .field("extra_middleware", &middleware_names)
            .field("supported_media_kinds", &self.supported_media_kinds)
            .field("init_kwargs", &self.init_kwargs)
            .field("context_window_tokens", &self.context_window_tokens)
            .field("general_purpose_subagent", &self.general_purpose_subagent)
            .finish()
    }
}
