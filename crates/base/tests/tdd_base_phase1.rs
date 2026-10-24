use base::error::PathValidationError;
use base::path::validate_and_normalize_path;
use base::platform::{RuntimePlatform, interpolate_env_vars};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_adversarial_paths(raw_path in ".*") {
        let res = validate_and_normalize_path(&raw_path);

        if raw_path.is_empty() {
            prop_assert_eq!(res, Err(PathValidationError::EmptyPath));
            return Ok(());
        }

        if raw_path.chars().any(|c| { let c = c as u32; c <= 0x1F || c == 0x7F }) {
            prop_assert_eq!(res, Err(PathValidationError::NullByteOrControlChar));
            return Ok(());
        }

        if raw_path.contains('\\') {
            prop_assert_eq!(res, Err(PathValidationError::BackslashForbidden));
            return Ok(());
        }

        if raw_path.split('/').any(|s| s == "." || s == "..") {
            prop_assert_eq!(res, Err(PathValidationError::TraversalAttempt));
            return Ok(());
        }

        // If it passed all constraints, ensure it's absolute and normalized
        if let Ok(normalized) = res {
            prop_assert!(normalized.starts_with('/'));
            prop_assert!(!normalized.contains("//"));
            if normalized.len() > 1 {
                prop_assert!(!normalized.ends_with('/'));
            }
        }
    }
}

#[test]
fn test_termux_path_rebasing() {
    let platform = RuntimePlatform::AndroidTermux {
        prefix: "/data/data/com.termux/files/usr".to_string(),
    };

    // Test that strict posix paths are left alone
    let strict_res = platform.rebase_path("/var/lib/tantry/data", true).unwrap();
    assert_eq!(strict_res, "/var/lib/tantry/data");

    // Test tantry specific rebases
    let t_data = platform.rebase_path("/var/lib/tantry/data", false).unwrap();
    assert_eq!(
        t_data,
        "/data/data/com.termux/files/usr/var/lib/tantry/data"
    );

    let spire_sock = platform
        .rebase_path("/run/spire/sockets/agent.sock", false)
        .unwrap();
    assert_eq!(
        spire_sock,
        "/data/data/com.termux/files/usr/var/run/spire/sockets/agent.sock"
    );

    let run_tantry = platform
        .rebase_path("/var/run/tantry/sandboxes", false)
        .unwrap();
    assert_eq!(
        run_tantry,
        "/data/data/com.termux/files/usr/var/run/tantry/sandboxes"
    );

    // Test binaries
    let bin = platform.rebase_path("/usr/bin/jailer", false).unwrap();
    assert_eq!(bin, "/data/data/com.termux/files/usr/bin/jailer");

    // Test paths that shouldn't be rebased or are already under prefix
    let already = platform
        .rebase_path("/data/data/com.termux/files/usr/var/lib/tantry/data", false)
        .unwrap();
    assert_eq!(
        already,
        "/data/data/com.termux/files/usr/var/lib/tantry/data"
    );
}

#[test]
fn test_interpolate_env_vars() {
    let env_lookup = |key: &str| -> Option<String> {
        match key {
            "PREFIX" => Some("/data/data/com.termux/files/usr".to_string()),
            "EMPTY_VAR" => Some("".to_string()),
            _ => None,
        }
    };

    // Basic substitution
    let res = interpolate_env_vars("${PREFIX}/var/lib/tantry", &env_lookup);
    assert_eq!(res, "/data/data/com.termux/files/usr/var/lib/tantry");

    // Default fallback when env is missing
    let res2 = interpolate_env_vars("${MISSING:-/usr}/bin/jailer", &env_lookup);
    assert_eq!(res2, "/usr/bin/jailer");

    // Default fallback when env is present but empty
    let res3 = interpolate_env_vars("${EMPTY_VAR:-/usr}/bin/jailer", &env_lookup);
    assert_eq!(res3, "/usr/bin/jailer");

    // Missing without default (should be stripped or left empty? spec says interpolate env vars, if missing standard shell replaces with empty)
    let res4 = interpolate_env_vars("${MISSING_NO_DEFAULT}/bin", &env_lookup);
    assert_eq!(res4, "/bin");
}
