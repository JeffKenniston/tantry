use base::ast::Message;
use base::delta::MessageDelta;
use base::typemap::*;

#[derive(Clone, Debug, PartialEq)]
pub struct MockSlot {
    pub data: String,
}
impl StateSlot for MockSlot {
    const WIRE_KEY: &'static str = "mock_private";
    const VISIBILITY: SlotVisibility = SlotVisibility::Private;
    const CODEC_TAG: CodecTag = CodecTag::RkyvAligned;
    fn encode_payload(&self) -> Result<Vec<u8>, base::error::ExtensionError> {
        Ok(self.data.as_bytes().to_vec())
    }
    fn decode_payload(bytes: &[u8]) -> Result<Self, base::error::ExtensionError> {
        Ok(Self {
            data: String::from_utf8(bytes.to_vec()).unwrap(),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SharedMockSlot {
    pub data: String,
}
impl StateSlot for SharedMockSlot {
    const WIRE_KEY: &'static str = "mock_shared";
    const VISIBILITY: SlotVisibility = SlotVisibility::Shared;
    const CODEC_TAG: CodecTag = CodecTag::MessagePackNamed;
    fn encode_payload(&self) -> Result<Vec<u8>, base::error::ExtensionError> {
        Ok(self.data.as_bytes().to_vec())
    }
    fn decode_payload(bytes: &[u8]) -> Result<Self, base::error::ExtensionError> {
        Ok(Self {
            data: String::from_utf8(bytes.to_vec()).unwrap(),
        })
    }
}

#[test]
fn test_state_extension_map_cow_isolation_and_hydration() {
    let mut map = StateExtensionMap::new();
    map.insert(MockSlot {
        data: "private_data".to_string(),
    });
    map.insert(SharedMockSlot {
        data: "shared_data".to_string(),
    });

    let forked = map.fork_shared_only();
    assert!(forked.get::<MockSlot>().is_none());
    assert!(forked.get::<SharedMockSlot>().is_some());

    let serialized = map.serialize_all().unwrap();
    let mut registry = DefaultExtensionRegistryImpl::new();
    register_slot::<MockSlot>(&mut registry);
    register_slot::<SharedMockSlot>(&mut registry);

    let mut new_map = StateExtensionMap::new();
    new_map.hydrate_all(&serialized, &registry).unwrap();

    assert_eq!(new_map.get::<MockSlot>().unwrap().data, "private_data");
    assert_eq!(new_map.get::<SharedMockSlot>().unwrap().data, "shared_data");
}

#[test]
fn test_message_delta_apply() {
    let msg1 = Message::user("test 1".to_string());
    let msg2 = Message::user("test 2".to_string());
    let msg3 = Message::user("test 3".to_string());

    let mut messages = vec![msg1.clone()];

    // Append
    let delta_append = MessageDelta::Append(vec![msg2.clone(), msg3.clone()]);
    let evicted = MessageDelta::apply(&mut messages, delta_append).unwrap();
    assert!(evicted.is_empty());
    assert_eq!(messages.len(), 3);

    // PatchById
    let id_to_patch = msg2.id;
    let mut patched_msg2 = msg2.clone();
    patched_msg2
        .metadata
        .insert("patched".to_string(), serde_json::Value::Bool(true));
    let delta_patch = MessageDelta::PatchById {
        target_id: id_to_patch,
        replacement: patched_msg2.clone(),
    };
    let evicted = MessageDelta::apply(&mut messages, delta_patch).unwrap();
    assert_eq!(evicted.len(), 1);
    assert_eq!(evicted[0].id, id_to_patch);
    assert!(messages[1].metadata.contains_key("patched"));

    // CompactRange
    let summary = Message::system("summary".to_string(), None);
    let delta_compact = MessageDelta::CompactRange {
        up_to_id_inclusive: id_to_patch,
        summary_message: summary.clone(),
    };
    let evicted = MessageDelta::apply(&mut messages, delta_compact).unwrap();
    assert_eq!(evicted.len(), 2);
    assert_eq!(evicted[0].id, msg1.id);
    assert_eq!(evicted[1].id, id_to_patch);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].id, summary.id);
    assert_eq!(messages[1].id, msg3.id);
}

use base::ast::FileData;
use base::vfs_tree::VfsTree;
use chrono::Utc;
use std::sync::Arc;

#[test]
fn test_vfs_diff_with_stats() {
    let mut before = VfsTree::new();
    let mut after = VfsTree::new();

    let f1 = Arc::new(FileData::new_utf8("file1".to_string(), Utc::now()));
    let f2 = Arc::new(FileData::new_utf8("file2".to_string(), Utc::now()));
    let f3 = Arc::new(FileData::new_utf8("file3".to_string(), Utc::now()));
    let f4 = Arc::new(FileData::new_utf8("file4".to_string(), Utc::now()));

    before
        .insert("/dir1/a.txt".to_string(), f1.clone())
        .unwrap();
    before
        .insert("/dir1/b.txt".to_string(), f2.clone())
        .unwrap();
    before
        .insert("/dir2/c.txt".to_string(), f3.clone())
        .unwrap();

    after.insert("/dir1/a.txt".to_string(), f1.clone()).unwrap();
    after.insert("/dir1/b.txt".to_string(), f4.clone()).unwrap();

    let (deltas, visited) = before.diff_with_stats(&after);
    assert_eq!(deltas.len(), 2);
    // visited nodes...
    assert!(visited.visited_nodes <= 2 * 2 * 3); // some reasonable upper bound based on K log N
}

use base::error::PathValidationError;
use base::path::validate_and_normalize_path;
use base::platform::{RuntimePlatform, interpolate_env_vars};
#[allow(unused_imports)]
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
    let res = interpolate_env_vars("${PREFIX}/var/lib/tantry", env_lookup);
    assert_eq!(res, "/data/data/com.termux/files/usr/var/lib/tantry");

    // Default fallback when env is missing
    let res2 = interpolate_env_vars("${MISSING:-/usr}/bin/jailer", env_lookup);
    assert_eq!(res2, "/usr/bin/jailer");

    // Default fallback when env is present but empty
    let res3 = interpolate_env_vars("${EMPTY_VAR:-/usr}/bin/jailer", env_lookup);
    assert_eq!(res3, "/usr/bin/jailer");

    // Missing without default (should be stripped or left empty? spec says interpolate env vars, if missing standard shell replaces with empty)
    let res4 = interpolate_env_vars("${MISSING_NO_DEFAULT}/bin", env_lookup);
    assert_eq!(res4, "/bin");
}
