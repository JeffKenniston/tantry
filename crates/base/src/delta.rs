use crate::ast::{FileData, Message, MessageId};
use crate::error::{PathValidationError, StateReducerError};
use crate::path::PosixPath;
use crate::vfs::VfsTree;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub enum MessageDelta {
    Append(Vec<Message>),
    PatchById {
        target_id: MessageId,
        replacement: Message,
    },
    CompactRange {
        up_to_id_inclusive: MessageId,
        summary_message: Message,
    },
}

impl MessageDelta {
    pub fn apply(
        messages: &mut Vec<Message>,
        delta: MessageDelta,
    ) -> Result<Vec<Message>, StateReducerError> {
        match delta {
            MessageDelta::Append(new_msgs) => {
                for msg in new_msgs {
                    if !messages.iter().any(|m| m.id == msg.id) {
                        messages.push(msg);
                    }
                }
                Ok(vec![])
            }
            MessageDelta::PatchById {
                target_id,
                replacement,
            } => {
                if let Some(idx) = messages.iter().position(|m| m.id == target_id) {
                    let evicted = std::mem::replace(&mut messages[idx], replacement);
                    Ok(vec![evicted])
                } else {
                    Err(StateReducerError::MessageIdNotFound(target_id))
                }
            }
            MessageDelta::CompactRange {
                up_to_id_inclusive,
                summary_message,
            } => {
                if let Some(idx) = messages.iter().position(|m| m.id == up_to_id_inclusive) {
                    let evicted: Vec<Message> = messages.drain(0..=idx).collect();
                    messages.insert(0, summary_message);
                    Ok(evicted)
                } else {
                    Err(StateReducerError::MessageIdNotFound(up_to_id_inclusive))
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileDelta {
    Upsert {
        path: PosixPath,
        data: Arc<FileData>,
    },
    Delete {
        path: PosixPath,
    },
}

impl FileDelta {
    pub fn apply_batch(
        tree: &mut VfsTree,
        deltas: &[FileDelta],
    ) -> Result<(), PathValidationError> {
        for delta in deltas {
            match delta {
                FileDelta::Upsert { path, data } => {
                    tree.insert(path.clone(), data.clone())?;
                }
                FileDelta::Delete { path } => {
                    tree.remove(path);
                }
            }
        }
        Ok(())
    }

    pub fn diff_trees(before: &VfsTree, after: &VfsTree) -> Vec<FileDelta> {
        before.diff(after)
    }
}
