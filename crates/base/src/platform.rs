use crate::error::PathValidationError;
use crate::path::{PosixPath, validate_and_normalize_path};

/// RuntimePlatform enum
pub enum RuntimePlatform {
    LinuxStandard,
    AndroidTermux { prefix: PosixPath },
}

/// interpolate_env_vars fn
pub fn interpolate_env_vars<F: Fn(&str) -> Option<String>>(input: &str, env_lookup: F) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            let mut default_val = None;
            let mut has_default = false;
            let mut default_str = String::new();

            while let Some(nc) = chars.next() {
                if nc == '}' {
                    break;
                } else if nc == ':' && chars.peek() == Some(&'-') {
                    chars.next(); // consume '-'
                    has_default = true;
                } else if has_default {
                    default_str.push(nc);
                } else {
                    var_name.push(nc);
                }
            }

            if has_default {
                default_val = Some(default_str);
            }

            if let Some(val) = env_lookup(&var_name) {
                if val.is_empty() && has_default {
                    if let Some(def) = default_val {
                        result.push_str(&def);
                    }
                } else {
                    result.push_str(&val);
                }
            } else if let Some(def) = default_val {
                result.push_str(&def);
            }
        } else {
            result.push(c);
        }
    }

    result
}

impl RuntimePlatform {
    /// detect_from_env fn
    pub fn detect_from_env<F>(env_lookup: F, is_android_target: bool) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let termux_version = env_lookup("TERMUX_VERSION").unwrap_or_default();
        let prefix = env_lookup("PREFIX").unwrap_or_default();

        if is_android_target
            || !termux_version.is_empty()
            || prefix.starts_with("/data/data/com.termux")
        {
            let actual_prefix = if prefix.is_empty() {
                "/data/data/com.termux/files/usr".to_string()
            } else {
                prefix
            };
            RuntimePlatform::AndroidTermux {
                prefix: actual_prefix,
            }
        } else {
            RuntimePlatform::LinuxStandard
        }
    }

    /// rebase_path fn
    pub fn rebase_path(
        &self,
        path: &str,
        strict_posix_paths: bool,
    ) -> Result<PosixPath, PathValidationError> {
        let normalized = validate_and_normalize_path(path)?;

        match self {
            RuntimePlatform::LinuxStandard => Ok(normalized),
            RuntimePlatform::AndroidTermux { prefix } => {
                if !strict_posix_paths {
                    if normalized.starts_with(prefix) {
                        return Ok(normalized);
                    }
                    if let Some(suffix) = normalized.strip_prefix("/var/lib/tantry") {
                        Ok(format!("{}/var/lib/tantry{}", prefix, suffix))
                    } else if let Some(suffix) = normalized.strip_prefix("/run/spire") {
                        Ok(format!("{}/var/run/spire{}", prefix, suffix))
                    } else if let Some(suffix) = normalized.strip_prefix("/var/run/tantry") {
                        Ok(format!("{}/var/run/tantry{}", prefix, suffix))
                    } else if let Some(suffix) = normalized.strip_prefix("/usr/bin/") {
                        Ok(format!("{}/bin/{}", prefix, suffix))
                    } else {
                        Ok(normalized)
                    }
                } else {
                    Ok(normalized)
                }
            }
        }
    }

    /// effective_max_workers fn
    pub fn effective_max_workers(&self, configured: usize) -> usize {
        match self {
            RuntimePlatform::LinuxStandard => configured.max(1),
            RuntimePlatform::AndroidTermux { .. } => configured.max(1).min(8),
        }
    }

    /// effective_rayon_threads fn
    pub fn effective_rayon_threads(&self, num_cpus: usize) -> usize {
        match self {
            RuntimePlatform::LinuxStandard => num_cpus.max(1),
            RuntimePlatform::AndroidTermux { .. } => num_cpus.max(1).min(4),
        }
    }
}
