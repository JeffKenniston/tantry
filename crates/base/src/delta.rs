use crate::ast::{Message, FileData, MessageId};
use crate::vfs_tree::VfsTree;

#[derive(Debug, Clone, PartialEq)]
pub enum MessageDelta {
    Append(Message),
    PatchById(MessageId, Message),
    CompactRange {
        up_to_id_inclusive: MessageId,
        summary_message: Message,
    },
}

impl MessageDelta {
    pub fn apply(messages: &mut Vec<Message>, delta: MessageDelta) -> Vec<Message> {
        let mut evicted = Vec::new();
        match delta {
            MessageDelta::Append(msg) => {
                if !messages.iter().any(|m| m.id == msg.id) {
                    messages.push(msg);
                }
            }
            MessageDelta::PatchById(id, new_msg) => {
                if let Some(pos) = messages.iter().position(|m| m.id == id) {
                    evicted.push(messages[pos].clone());
                    messages[pos] = new_msg;
                }
            }
            MessageDelta::CompactRange { up_to_id_inclusive, summary_message } => {
                if let Some(pos) = messages.iter().position(|m| m.id == up_to_id_inclusive) {
                    let range_evicted: Vec<_> = messages.drain(0..=pos).collect();
                    evicted.extend(range_evicted);
                    messages.insert(0, summary_message);
                }
            }
        }
        evicted
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileDelta {
    Upsert { path: String, file: FileData },
    Delete { path: String },
}

impl FileDelta {
    pub fn apply_batch(tree: &mut VfsTree, deltas: Vec<FileDelta>) {
        for delta in deltas {
            match delta {
                FileDelta::Upsert { path, file } => {
                    tree.insert(&path, file);
                }
                FileDelta::Delete { path } => {
                    tree.remove(&path);
                }
            }
        }
    }

    pub fn diff_trees(a: &VfsTree, b: &VfsTree) -> Vec<FileDelta> {
        a.diff(b)
    }
}
