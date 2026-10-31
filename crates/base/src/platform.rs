use crate::error::PathValidationError;
use crate::path::{PosixPath, validate_and_normalize_path};

pub fn interpolate_env_vars<F: Fn(&str) -> Option<String>>(input: &str, env_lookup: F) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            let mut default_val = None;
            let mut has_default = false;

            while let Some(inner_c) = chars.next() {
                if inner_c == '}' {
                    break;
                } else if inner_c == ':' && chars.peek() == Some(&'-') {
                    chars.next(); // consume '-'
                    has_default = true;
                    let mut default_str = String::new();
                    while let Some(def_c) = chars.next() {
                        if def_c == '}' {
                            break;
                        }
                        default_str.push(def_c);
                    }
                    default_val = Some(default_str);
                    break;
                } else {
                    var_name.push(inner_c);
                }
            }

            if let Some(val) = env_lookup(&var_name) {
                result.push_str(&val);
            } else if let Some(def) = default_val {
                result.push_str(&def);
            } else if !has_default {
                // Keep empty if no default provided
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
        let termux_ver = env_lookup("TERMUX_VERSION");
        let prefix_env = env_lookup("PREFIX");

        let is_termux = is_android_target
            || termux_ver.map_or(false, |s| !s.is_empty())
            || prefix_env.as_ref().map_or(false, |s| s.starts_with("/data/data/com.termux"));

        if is_termux {
            let prefix = prefix_env.unwrap_or_else(|| "/data/data/com.termux/files/usr".to_string());
            Self::AndroidTermux { prefix }
        } else {
            Self::LinuxStandard
        }
    }

    pub fn rebase_path(&self, path: &str, strict_posix_paths: bool) -> Result<PosixPath, PathValidationError> {
        let norm_path = validate_and_normalize_path(path)?;

        match self {
            Self::AndroidTermux { prefix } if !strict_posix_paths => {
                if norm_path.starts_with("/var/lib/tantry") && !norm_path.starts_with(prefix) {
                    let suffix = &norm_path["/var/lib/tantry".len()..];
                    let mut new_path = format!("{}/var/lib/tantry", prefix);
                    if !suffix.is_empty() {
                        if !suffix.starts_with('/') {
                            new_path.push('/');
                        }
                        new_path.push_str(suffix);
                    }
                    Ok(new_path)
                } else if norm_path.starts_with("/run/spire") {
                    let suffix = &norm_path["/run/spire".len()..];
                    let mut new_path = format!("{}/var/run/spire", prefix);
                    if !suffix.is_empty() {
                        if !suffix.starts_with('/') {
                            new_path.push('/');
                        }
                        new_path.push_str(suffix);
                    }
                    Ok(new_path)
                } else if norm_path.starts_with("/var/run/tantry") {
                    let suffix = &norm_path["/var/run/tantry".len()..];
                    let mut new_path = format!("{}/var/run/tantry", prefix);
                    if !suffix.is_empty() {
                        if !suffix.starts_with('/') {
                            new_path.push('/');
                        }
                        new_path.push_str(suffix);
                    }
                    Ok(new_path)
                } else {
                    Ok(norm_path)
                }
            },
            _ => Ok(norm_path),
        }
    }

    pub fn effective_max_workers(&self, configured: usize) -> usize {
        match self {
            Self::AndroidTermux { .. } => configured.clamp(1, 8),
            Self::LinuxStandard => configured.max(1),
        }
    }
}
