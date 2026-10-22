use crate::error::PathValidationError;
use crate::path::{PosixPath, validate_and_normalize_path};

pub fn interpolate_env_vars<F: Fn(&str) -> Option<String>>(input: &str, env_lookup: F) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' {
            if let Some(&'{') = chars.peek() {
                chars.next(); // Consume '{'
                let mut var_name = String::new();
                let mut default_value = None;
                let mut in_default = false;

                while let Some(inner_c) = chars.next() {
                    if inner_c == '}' {
                        break;
                    } else if inner_c == ':' && chars.peek() == Some(&'-') {
                        chars.next(); // Consume '-'
                        in_default = true;
                        default_value = Some(String::new());
                    } else if in_default {
                        if let Some(def) = default_value.as_mut() {
                            def.push(inner_c);
                        }
                    } else {
                        var_name.push(inner_c);
                    }
                }

                if let Some(val) = env_lookup(&var_name) {
                    result.push_str(&val);
                } else if let Some(def) = default_value {
                    result.push_str(&def);
                }
            } else {
                result.push('$');
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimePlatform {
    LinuxStandard,
    AndroidTermux { prefix: PosixPath },
}

impl RuntimePlatform {
    pub fn detect_from_env<F>(env_lookup: F, is_android_target: bool) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let termux_version = env_lookup("TERMUX_VERSION").unwrap_or_default();
        let prefix = env_lookup("PREFIX").unwrap_or_default();

        let is_termux = is_android_target
            || !termux_version.is_empty()
            || prefix.starts_with("/data/data/com.termux");

        if is_termux {
            let prefix_path = if !prefix.is_empty() {
                prefix
            } else {
                "/data/data/com.termux/files/usr".to_string()
            };
            RuntimePlatform::AndroidTermux {
                prefix: prefix_path,
            }
        } else {
            RuntimePlatform::LinuxStandard
        }
    }

    pub fn rebase_path(
        &self,
        path: &str,
        strict_posix_paths: bool,
    ) -> Result<PosixPath, PathValidationError> {
        let normalized = validate_and_normalize_path(path)?;

        if let RuntimePlatform::AndroidTermux { prefix } = self
            && !strict_posix_paths
        {
            if normalized.starts_with("/var/lib/tantry") && !normalized.starts_with(prefix) {
                let suffix = normalized.strip_prefix("/var/lib/tantry").unwrap_or("");
                return validate_and_normalize_path(&format!("{}/var/lib/tantry{}", prefix, suffix));
            } else if normalized.starts_with("/run/spire") && !normalized.starts_with(prefix) {
                let suffix = normalized.strip_prefix("/run/spire").unwrap_or("");
                return validate_and_normalize_path(&format!("{}/var/run/spire{}", prefix, suffix));
            } else if normalized.starts_with("/var/run/tantry") && !normalized.starts_with(prefix) {
                let suffix = normalized.strip_prefix("/var/run/tantry").unwrap_or("");
                return validate_and_normalize_path(&format!(
                    "{}/var/run/tantry{}",
                    prefix, suffix
                ));
            }
        }

        Ok(normalized)
    }

    pub fn effective_max_workers(&self, configured: usize) -> usize {
        let min_workers = configured.max(1);
        match self {
            RuntimePlatform::AndroidTermux { .. } => min_workers.min(8),
            RuntimePlatform::LinuxStandard => min_workers,
        }
    }
}
