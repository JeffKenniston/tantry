use std::collections::{BTreeMap, BTreeSet};

use crate::error::ProfileError;
use crate::schema::{HarnessProfile, HarnessProfileOverride, parse_profile_key};
use base::ast::MediaKind;

#[derive(Clone, Debug)]
pub struct ProfileRegistry {
    pub base_profiles: BTreeMap<String, HarnessProfile>,
    pub model_overrides: BTreeMap<String, HarnessProfileOverride>,
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileRegistry {
    pub fn new() -> Self {
        let mut base_profiles = BTreeMap::new();
        let mut model_overrides = BTreeMap::new();

        // 1. anthropic
        let mut anthropic = HarnessProfile {
            profile_key: "anthropic".to_string(),
            system_prompt_prefix: None,
            system_prompt_suffix: None,
            excluded_tools: BTreeSet::new(),
            excluded_middleware: BTreeSet::new(),
            tool_description_overrides: BTreeMap::new(),
            extra_middleware: vec![],
            supported_media_kinds: Some(vec![MediaKind::Image, MediaKind::Document]),
            init_kwargs: BTreeMap::new(),
            context_window_tokens: 200_000,
            general_purpose_subagent: None,
        };
        anthropic.init_kwargs.insert(
            "anthropic_beta".to_string(),
            serde_json::Value::String("prompt-caching-2024-07-31".to_string()),
        );
        base_profiles.insert("anthropic".to_string(), anthropic);

        // 2. google_genai
        let google_genai = HarnessProfile {
            profile_key: "google_genai".to_string(),
            system_prompt_prefix: None,
            system_prompt_suffix: None,
            excluded_tools: BTreeSet::new(),
            excluded_middleware: BTreeSet::new(),
            tool_description_overrides: BTreeMap::new(),
            extra_middleware: vec![],
            supported_media_kinds: Some(vec![
                MediaKind::Image,
                MediaKind::Audio,
                MediaKind::Video,
                MediaKind::Document,
            ]),
            init_kwargs: BTreeMap::new(),
            context_window_tokens: 1_000_000,
            general_purpose_subagent: None,
        };
        base_profiles.insert("google_genai".to_string(), google_genai);

        // 3. openai
        let openai = HarnessProfile {
            profile_key: "openai".to_string(),
            system_prompt_prefix: None,
            system_prompt_suffix: None,
            excluded_tools: BTreeSet::new(),
            excluded_middleware: BTreeSet::new(),
            tool_description_overrides: BTreeMap::new(),
            extra_middleware: vec![],
            supported_media_kinds: Some(vec![
                MediaKind::Image,
                MediaKind::Audio,
                MediaKind::Document,
            ]),
            init_kwargs: BTreeMap::new(),
            context_window_tokens: 128_000,
            general_purpose_subagent: None,
        };
        base_profiles.insert("openai".to_string(), openai);

        // 4. local_vllm
        let local_vllm = HarnessProfile {
            profile_key: "local_vllm".to_string(),
            system_prompt_prefix: None,
            system_prompt_suffix: None,
            excluded_tools: BTreeSet::new(),
            excluded_middleware: BTreeSet::new(),
            tool_description_overrides: BTreeMap::new(),
            extra_middleware: vec![],
            supported_media_kinds: Some(vec![MediaKind::Image]),
            init_kwargs: BTreeMap::new(),
            context_window_tokens: 32_768,
            general_purpose_subagent: None,
        };
        base_profiles.insert("local_vllm".to_string(), local_vllm);

        // Pre-register built-in model overrides:
        // anthropic:claude-3-7-sonnet
        let mut claude_override = HarnessProfileOverride::default();
        claude_override.init_kwargs.insert(
            "thinking_budget_tokens".to_string(),
            serde_json::Value::Number(serde_json::Number::from(16384)),
        );
        model_overrides.insert("anthropic:claude-3-7-sonnet".to_string(), claude_override);

        // google_genai:gemini-3.1-pro:preview
        let mut gemini_override = HarnessProfileOverride::default();
        gemini_override.context_window_tokens = Some(2_000_000);
        gemini_override.init_kwargs.insert(
            "thinking_level".to_string(),
            serde_json::Value::String("high".to_string()),
        );
        model_overrides.insert(
            "google_genai:gemini-3.1-pro:preview".to_string(),
            gemini_override,
        );

        // openai:o3-mini
        let mut o3_override = HarnessProfileOverride::default();
        o3_override.context_window_tokens = Some(200_000);
        o3_override.supported_media_kinds = Some(vec![]);
        model_overrides.insert("openai:o3-mini".to_string(), o3_override);

        Self {
            base_profiles,
            model_overrides,
        }
    }

    pub fn register_base_profile(&mut self, provider: impl Into<String>, profile: HarnessProfile) {
        self.base_profiles.insert(provider.into(), profile);
    }

    pub fn register_model_override(
        &mut self,
        full_key: impl Into<String>,
        ovr: HarnessProfileOverride,
    ) {
        self.model_overrides.insert(full_key.into(), ovr);
    }

    pub fn resolve(&self, key: &str) -> Result<HarnessProfile, ProfileError> {
        let (provider, model_opt) = parse_profile_key(key)?;

        let mut resolved = match self.base_profiles.get(provider) {
            Some(profile) => profile.clone(),
            None => return Err(ProfileError::UnknownProvider(provider.to_string())),
        };

        resolved.profile_key = key.to_string();

        if let Some(model_name) = model_opt {
            if let Some(ovr) = self.model_overrides.get(key) {
                resolved.apply_override(ovr);
            } else if let Some(ovr) = self.model_overrides.get(model_name) {
                resolved.apply_override(ovr);
            }
        }

        Ok(resolved)
    }

    pub fn resolve_with_caller_override(
        &self,
        key: &str,
        caller_override: Option<&HarnessProfileOverride>,
    ) -> Result<HarnessProfile, ProfileError> {
        let mut profile = self.resolve(key)?;

        if let Some(ovr) = caller_override {
            profile.apply_override(ovr);
        }

        Ok(profile)
    }
}
