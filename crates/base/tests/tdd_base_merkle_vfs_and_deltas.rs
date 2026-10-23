use base::error::PathValidationError;
use base::path::validate_and_normalize_path;

use base::vfs_tree::VfsTree;
use base::delta::{FileDelta, MessageDelta};
use base::ast::{Message, FileData};
use std::sync::Arc;
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
fn test_vfs_diff_and_deltas() {
    let mut tree1 = VfsTree::new();
    let mut tree2 = VfsTree::new();

    let now = chrono::Utc::now();
    let file1 = Arc::new(FileData::new_utf8("hello".to_string(), now));
    let file2 = Arc::new(FileData::new_utf8("world".to_string(), now));
    let file3 = Arc::new(FileData::new_utf8("foo".to_string(), now));

    tree1.insert("/a/b/c.txt".to_string(), file1.clone()).unwrap();
    tree1.insert("/a/b/d.txt".to_string(), file2.clone()).unwrap();
    tree1.insert("/e/f.txt".to_string(), file3.clone()).unwrap();

    tree2.insert("/a/b/c.txt".to_string(), file1.clone()).unwrap();
    let file2_mod = Arc::new(FileData::new_utf8("world_mod".to_string(), now));
    tree2.insert("/a/b/d.txt".to_string(), file2_mod.clone()).unwrap();
    let file4 = Arc::new(FileData::new_utf8("bar".to_string(), now));
    tree2.insert("/g/h.txt".to_string(), file4.clone()).unwrap();

    let (deltas, visited) = tree1.diff_with_stats(&tree2);

    assert_eq!(deltas.len(), 3);
    assert!(visited <= 2 * 4 * 3); // 2 * K(4) * max_depth(3)

    let mut upsert_d = false;
    let mut delete_f = false;
    let mut upsert_h = false;

    for delta in deltas {
        match delta {
            FileDelta::Upsert { path, data } => {
                if path == "/a/b/d.txt" {
                    assert_eq!(data.blake3_hash, file2_mod.blake3_hash);
                    upsert_d = true;
                } else if path == "/g/h.txt" {
                    assert_eq!(data.blake3_hash, file4.blake3_hash);
                    upsert_h = true;
                } else {
                    panic!("Unexpected Upsert: {}", path);
                }
            }
            FileDelta::Delete { path } => {
                if path == "/e/f.txt" {
                    delete_f = true;
                } else {
                    panic!("Unexpected Delete: {}", path);
                }
            }
        }
    }

    assert!(upsert_d);
    assert!(delete_f);
    assert!(upsert_h);
}

#[test]
fn test_message_deltas() {
    let mut messages = Vec::new();
    let msg1 = Message::user("test1".to_string());
    let msg2 = Message::assistant(vec![]);
    let msg3 = Message::user("test3".to_string());

    // Test Append
    let delta = MessageDelta::Append(vec![msg1.clone(), msg2.clone()]);
    let evicted = MessageDelta::apply(&mut messages, delta).unwrap();
    assert!(evicted.is_empty());
    assert_eq!(messages.len(), 2);

    // Test PatchById
    let mut msg2_mod = msg2.clone();
    msg2_mod.metadata.insert("key".to_string(), serde_json::json!("val"));
    let delta = MessageDelta::PatchById { target_id: msg2.id, replacement: msg2_mod.clone() };
    let evicted = MessageDelta::apply(&mut messages, delta).unwrap();
    assert_eq!(evicted.len(), 1);
    assert_eq!(evicted[0].id, msg2.id);
    assert_eq!(messages[1].id, msg2_mod.id);
    assert!(messages[1].metadata.contains_key("key"));

    // Test CompactRange
    messages.push(msg3.clone());
    let summary = Message::system("summary".to_string(), None);
    let delta = MessageDelta::CompactRange { up_to_id_inclusive: msg2_mod.id, summary_message: summary.clone() };
    let evicted = MessageDelta::apply(&mut messages, delta).unwrap();
    assert_eq!(evicted.len(), 2);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].id, summary.id);
    assert_eq!(messages[1].id, msg3.id);
}
