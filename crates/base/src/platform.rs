use crate::path::PosixPath;
use std::env;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimePlatform {
    LinuxStandard,
    AndroidTermux { prefix: PosixPath },
}

impl RuntimePlatform {
    pub fn detect_from_env() -> Self {
        let is_android_target = cfg!(target_os = "android");
        let termux_version = env::var("TERMUX_VERSION").unwrap_or_default();
        let prefix = env::var("PREFIX").unwrap_or_default();

        let is_termux = is_android_target
            || !termux_version.is_empty()
            || prefix.starts_with("/data/data/com.termux");

        if is_termux {
            let default_prefix = "/data/data/com.termux/files/usr".to_string();
            let actual_prefix = if prefix.is_empty() { default_prefix } else { prefix };
            RuntimePlatform::AndroidTermux { prefix: actual_prefix }
        } else {
            RuntimePlatform::LinuxStandard
        }
    }

    pub fn rebase_path(&self, path: &str, strict_posix_paths: bool) -> String {
        match self {
            RuntimePlatform::AndroidTermux { prefix } if !strict_posix_paths => {
                if path.starts_with("/var/lib/tantry") {
                    path.replacen("/var/lib/tantry", &format!("{}/var/lib/tantry", prefix), 1)
                } else if path.starts_with("/run/spire") {
                    path.replacen("/run/spire", &format!("{}/run/spire", prefix), 1)
                } else if path.starts_with("/var/run/tantry") {
                    path.replacen("/var/run/tantry", &format!("{}/var/run/tantry", prefix), 1)
                } else {
                    path.to_string()
                }
            }
            _ => path.to_string(),
        }
    }

    pub fn effective_max_workers(&self, configured: usize) -> usize {
        let configured = std::cmp::max(configured, 1);
        match self {
            RuntimePlatform::AndroidTermux { .. } => std::cmp::min(configured, 8),
            RuntimePlatform::LinuxStandard => configured,
        }
    }
}

pub fn interpolate_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_decl = String::new();
            while let Some(&nc) = chars.peek() {
                if nc == '}' {
                    chars.next(); // consume '}'
                    break;
                }
                var_decl.push(chars.next().unwrap());
            }

            // check for ${VAR:-default}
            if let Some(idx) = var_decl.find(":-") {
                let var_name = &var_decl[..idx];
                let default_val = &var_decl[idx + 2..];
                if let Ok(val) = env::var(var_name) {
                    if val.is_empty() {
                        result.push_str(default_val);
                    } else {
                        result.push_str(&val);
                    }
                } else {
                    result.push_str(default_val);
                }
            } else {
                // just ${VAR}
                if let Ok(val) = env::var(&var_decl) {
                    result.push_str(&val);
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpolation() {
        unsafe { env::set_var("TEST_VAR", "foo"); }
        assert_eq!(interpolate_env_vars("bar/${TEST_VAR}/baz"), "bar/foo/baz");
        assert_eq!(interpolate_env_vars("bar/${MISSING_VAR:-default}/baz"), "bar/default/baz");
        assert_eq!(interpolate_env_vars("bar/${TEST_VAR:-default}/baz"), "bar/foo/baz");
        unsafe { env::set_var("EMPTY_VAR", ""); }
        assert_eq!(interpolate_env_vars("bar/${EMPTY_VAR:-default}/baz"), "bar/default/baz");
    }

    #[test]
    fn test_rebasing() {
        let platform = RuntimePlatform::AndroidTermux { prefix: "/termux".to_string() };
        assert_eq!(platform.rebase_path("/var/lib/tantry/data", false), "/termux/var/lib/tantry/data");
        assert_eq!(platform.rebase_path("/run/spire/sockets", false), "/termux/run/spire/sockets");
        assert_eq!(platform.rebase_path("/other/path", false), "/other/path");

        assert_eq!(platform.rebase_path("/var/lib/tantry/data", true), "/var/lib/tantry/data");
    }

    #[test]
    fn test_workers() {
        let platform = RuntimePlatform::AndroidTermux { prefix: "/termux".to_string() };
        assert_eq!(platform.effective_max_workers(10), 8);
        assert_eq!(platform.effective_max_workers(4), 4);
        assert_eq!(platform.effective_max_workers(0), 1);

        let linux = RuntimePlatform::LinuxStandard;
        assert_eq!(linux.effective_max_workers(10), 10);
        assert_eq!(linux.effective_max_workers(0), 1);
    }
}
