use base::ast::{ContentBlock, FileData, Message};
use base::delta::{FileDelta, MessageDelta};
use base::path::validate_and_normalize_path;
use base::platform::RuntimePlatform;
use base::typemap::{
    CodecTag, SlotVisibility, StateExtensionMap, StateExtensionRegistry, StateSlot,
    register_slot,
};
use base::vfs::VfsTree;
use chrono::Utc;
use proptest::prelude::*;
use std::sync::Arc;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(25000))]
    #[test]
    fn test_path_normalization_adversarial(raw in ".*") {
        let normalized = validate_and_normalize_path(&raw);
        if let Ok(path) = normalized {
            assert!(!path.is_empty());
            assert!(path.starts_with('/'));
            assert!(!path.contains('\\'));
            assert!(!path.contains('\0'));
            assert!(!path.split('/').any(|s| s == ".." || s == "."));
        }
    }
}

#[test]
fn test_vfs_diff_and_stats() {
    let mut tree_before = VfsTree::new();
    let mut tree_after = VfsTree::new();
    let now = Utc::now();

    let data1 = Arc::new(FileData::new_utf8("hello".into(), now));
    let data2 = Arc::new(FileData::new_utf8("world".into(), now));
    let data2_mod = Arc::new(FileData::new_utf8("world2".into(), now));

    tree_before
        .insert("/dir1/file1.txt".into(), data1.clone())
        .unwrap();
    tree_before
        .insert("/dir2/file2.txt".into(), data2.clone())
        .unwrap();

    tree_after
        .insert("/dir1/file1.txt".into(), data1.clone())
        .unwrap(); // same
    tree_after
        .insert("/dir2/file2.txt".into(), data2_mod.clone())
        .unwrap(); // modified
    tree_after
        .insert("/dir2/file3.txt".into(), data1.clone())
        .unwrap(); // added
    tree_after
        .insert("/dir3/file4.txt".into(), data2.clone())
        .unwrap(); // added new dir

    let (deltas, visited) = tree_before.diff_with_stats(&tree_after);
    assert!(visited <= 20); // Not exploring unchanged subtrees, just verifying bound

    let expected_deltas = vec![
        FileDelta::Upsert {
            path: "/dir2/file2.txt".into(),
            data: data2_mod.clone(),
        },
        FileDelta::Upsert {
            path: "/dir2/file3.txt".into(),
            data: data1.clone(),
        },
        FileDelta::Upsert {
            path: "/dir3/file4.txt".into(),
            data: data2.clone(),
        },
    ];

    assert_eq!(deltas.len(), expected_deltas.len());
    for expected in expected_deltas {
        assert!(deltas.contains(&expected));
    }

    // Test that applying the batch makes them identical
    let mut tree_migrated = tree_before.clone();
    FileDelta::apply_batch(&mut tree_migrated, &deltas).unwrap();

    assert_eq!(tree_migrated.root_hash(), tree_after.root_hash());
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DummyExt {
    val: u32,
}
impl StateSlot for DummyExt {
    const WIRE_KEY: &'static str = "dummy";
    const VISIBILITY: SlotVisibility = SlotVisibility::Shared;
    const CODEC_TAG: CodecTag = CodecTag::MessagePackNamed;
    fn encode_payload(&self) -> Result<Vec<u8>, base::error::ExtensionError> {
        Ok(self.val.to_le_bytes().to_vec())
    }
    fn decode_payload(bytes: &[u8]) -> Result<Self, base::error::ExtensionError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(&bytes[..4]);
        Ok(Self {
            val: u32::from_le_bytes(b),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrivExt {
    secret: String,
}
impl StateSlot for PrivExt {
    const WIRE_KEY: &'static str = "priv";
    const VISIBILITY: SlotVisibility = SlotVisibility::Private;
    const CODEC_TAG: CodecTag = CodecTag::RkyvAligned;
    fn encode_payload(&self) -> Result<Vec<u8>, base::error::ExtensionError> {
        Ok(self.secret.as_bytes().to_vec())
    }
    fn decode_payload(bytes: &[u8]) -> Result<Self, base::error::ExtensionError> {
        Ok(Self {
            secret: String::from_utf8_lossy(bytes).into_owned(),
        })
    }
}

#[test]
fn test_extension_map_cow_and_hydration() {
    let mut map = StateExtensionMap::new();
    map.insert(DummyExt { val: 42 });
    map.insert(PrivExt {
        secret: "123".into(),
    });

    let forked = map.fork_shared_only();
    assert!(forked.get::<DummyExt>().is_some());
    assert!(forked.get::<PrivExt>().is_none());

    let mut registry = StateExtensionRegistry::new();
    register_slot::<DummyExt>(&mut registry);
    register_slot::<PrivExt>(&mut registry);

    let serialized = map.serialize_all().unwrap();

    let mut new_map = StateExtensionMap::new();
    new_map.hydrate_all(&serialized, &registry).unwrap();

    assert_eq!(new_map.get::<DummyExt>().unwrap().val, 42);
    assert_eq!(new_map.get::<PrivExt>().unwrap().secret, "123");
}

#[test]
fn test_message_deltas() {
    let mut msgs = vec![Message::user("Hello".into())];
    let msg1_id = msgs[0].id;

    let msg2 = Message::assistant(vec![ContentBlock::Text {
        text: "World".into(),
        cache_control: None,
    }]);
    let msg2_id = msg2.id;

    MessageDelta::apply(&mut msgs, MessageDelta::Append(vec![msg2.clone()])).unwrap();
    assert_eq!(msgs.len(), 2);

    let patched = Message::user("Hello!".into());
    // Patch by ID
    let mut replacement = patched.clone();
    replacement.id = msg1_id;
    let evicted = MessageDelta::apply(
        &mut msgs,
        MessageDelta::PatchById {
            target_id: msg1_id,
            replacement: replacement.clone(),
        },
    )
    .unwrap();

    assert_eq!(msgs[0].content, replacement.content);
    assert_eq!(evicted.len(), 1);

    // Compact
    let summary = Message::system("Summary".into(), None);
    let evicted = MessageDelta::apply(
        &mut msgs,
        MessageDelta::CompactRange {
            up_to_id_inclusive: msg2_id,
            summary_message: summary.clone(),
        },
    )
    .unwrap();

    assert_eq!(evicted.len(), 2);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].id, summary.id);
}

#[test]
fn test_platform_rebasing() {
    let env_lookup = |k: &str| -> Option<String> {
        if k == "PREFIX" {
            Some("/data/data/com.termux/files/usr".into())
        } else {
            None
        }
    };

    let platform = RuntimePlatform::detect_from_env(env_lookup, false);

    match platform {
        RuntimePlatform::AndroidTermux { ref prefix } => {
            assert_eq!(prefix, "/data/data/com.termux/files/usr");
        }
        _ => panic!("Expected Termux"),
    }

    let rebased = platform
        .rebase_path("/var/lib/tantry/db.sqlite", false)
        .unwrap();
    assert_eq!(
        rebased,
        "/data/data/com.termux/files/usr/var/lib/tantry/db.sqlite"
    );

    assert_eq!(platform.effective_max_workers(100), 8);
    assert_eq!(platform.effective_max_workers(0), 1);
}
