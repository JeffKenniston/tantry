use crate::path::PosixPath;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// MessageId type
pub type MessageId = Uuid;
/// ToolCallId type
pub type ToolCallId = String;
/// TaskId type
pub type TaskId = String;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug, PartialEq, Eq))]
/// McpSamplingDepthSlot struct
pub struct McpSamplingDepthSlot { pub depth: u32 }

impl crate::typemap::StateSlot for McpSamplingDepthSlot {
    const WIRE_KEY: &'static str = "tantry.cognitive.mcp_sampling_depth";
    const VISIBILITY: crate::typemap::SlotVisibility = crate::typemap::SlotVisibility::Private;
    const CODEC_TAG: crate::typemap::CodecTag = crate::typemap::CodecTag::RkyvAligned;

    fn encode_payload(&self) -> Result<Vec<u8>, crate::error::ExtensionError> {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(self).map_err(|e| crate::error::ExtensionError::SerializationFailed(e.to_string()))?;
        Ok(bytes.into_vec())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, crate::error::ExtensionError> {
        let archived = rkyv::access::<rkyv::Archived<Self>, rkyv::rancor::Error>(bytes).map_err(|e| crate::error::ExtensionError::SerializationFailed(e.to_string()))?;
        let deserialized: Self = rkyv::deserialize::<Self, rkyv::rancor::Error>(archived).map_err(|e| crate::error::ExtensionError::SerializationFailed(e.to_string()))?;
        Ok(deserialized)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Role enum
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// MediaKind enum
pub enum MediaKind {
    Image,
    Video,
    Audio,
    Document,
}

impl MediaKind {
    /// from_extension fn
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "jpg" | "jpeg" | "png" | "webp" | "gif" => Some(MediaKind::Image),
            "mp4" | "webm" | "mkv" => Some(MediaKind::Video),
            "mp3" | "wav" | "ogg" | "flac" => Some(MediaKind::Audio),
            "pdf" | "txt" | "md" | "csv" => Some(MediaKind::Document),
            _ => None,
        }
    }

    /// from_mime fn
    pub fn from_mime(mime: &str) -> Option<Self> {
        let mime = mime.to_lowercase();
        if mime.starts_with("image/") {
            Some(MediaKind::Image)
        } else if mime.starts_with("video/") {
            Some(MediaKind::Video)
        } else if mime.starts_with("audio/") {
            Some(MediaKind::Audio)
        } else if mime.starts_with("application/pdf") || mime.starts_with("text/") {
            Some(MediaKind::Document)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// CacheControl enum
pub enum CacheControl {
    Ephemeral,
    Persistent { ttl_seconds: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// ExecuteArtifact struct
pub struct ExecuteArtifact {
    pub exit_code: i32,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub peak_rss_bytes: Option<u64>,
    pub sandbox_id: String,
    pub isolation_tier: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// BlastRadiusReport struct
pub struct BlastRadiusReport {
    pub target_symbol: String,
    pub affected_files: Vec<PosixPath>,
    pub reverse_dependency_count: usize,
    pub max_depth_reached: usize,
    pub katz_centrality: f32,
    pub signature_mutated: bool,
    pub risk_score: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// ToolArtifact enum
pub enum ToolArtifact {
    Execute(ExecuteArtifact),
    BlastRadius(BlastRadiusReport),
    McpUiResource { uri: String, mime_type: String },
    Custom(serde_json::Value),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// ContentBlock enum
pub enum ContentBlock {
    Text {
        text: String,
        cache_control: Option<CacheControl>,
    },
    Reasoning {
        thought_summary: String,
        #[serde(skip)]
        opaque_signature: Option<Bytes>,
    },
    Media {
        kind: MediaKind,
        mime_type: String,
        #[serde(skip)]
        data: Bytes,
        source_path: Option<PosixPath>,
    },
    ToolUse {
        id: ToolCallId,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: ToolCallId,
        is_error: bool,
        content: Vec<ContentBlock>,
        artifact: Option<ToolArtifact>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// Message struct
pub struct Message {
    pub id: MessageId,
    pub role: Role,
    pub content: Vec<ContentBlock>,
    pub created_at: DateTime<Utc>,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl Message {
    /// user fn
    pub fn user(text: String) -> Self {
        Self {
            id: Uuid::now_v7(),
            role: Role::User,
            content: vec![ContentBlock::Text {
                text,
                cache_control: None,
            }],
            created_at: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    /// system fn
    pub fn system(text: String, cache_control: Option<CacheControl>) -> Self {
        Self {
            id: Uuid::now_v7(),
            role: Role::System,
            content: vec![ContentBlock::Text {
                text,
                cache_control,
            }],
            created_at: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    /// assistant fn
    pub fn assistant(content: Vec<ContentBlock>) -> Self {
        Self {
            id: Uuid::now_v7(),
            role: Role::Assistant,
            content,
            created_at: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    /// tool_result fn
    pub fn tool_result(
        tool_use_id: ToolCallId,
        is_error: bool,
        text: String,
        artifact: Option<ToolArtifact>,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id,
                is_error,
                content: vec![ContentBlock::Text {
                    text,
                    cache_control: None,
                }],
                artifact,
            }],
            created_at: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    /// assistant_text fn
    pub fn assistant_text(&self) -> Option<String> {
        if self.role != Role::Assistant {
            return None;
        }

        let texts: Vec<&str> = self
            .content
            .iter()
            .filter_map(|block| {
                if let ContentBlock::Text { text, .. } = block {
                    if !text.is_empty() {
                        Some(text.as_str())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        if texts.is_empty() {
            None
        } else {
            Some(texts.join("\n"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// TodoStatus enum
pub enum TodoStatus {
    Pending,
    InProgress,
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// TodoItem struct
pub struct TodoItem {
    pub id: String,
    pub content: String,
    pub status: TodoStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// FileData struct
pub struct FileData {
    pub content: Bytes,
    pub blake3_hash: [u8; 32],
    pub is_utf8: bool,
    pub mime_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

impl FileData {
    /// new_utf8 fn
    pub fn new_utf8(text: String, now: DateTime<Utc>) -> Self {
        let content = Bytes::from(text.clone());
        let hash = blake3::hash(&content).into();
        Self {
            content,
            blake3_hash: hash,
            is_utf8: true,
            mime_type: Some("text/plain".to_string()),
            created_at: now,
            modified_at: now,
        }
    }

    /// new_binary fn
    pub fn new_binary(bytes: Bytes, mime_type: Option<String>, now: DateTime<Utc>) -> Self {
        let hash = blake3::hash(&bytes).into();
        let is_utf8 = std::str::from_utf8(&bytes).is_ok();
        Self {
            content: bytes,
            blake3_hash: hash,
            is_utf8,
            mime_type,
            created_at: now,
            modified_at: now,
        }
    }

    /// as_str fn
    pub fn as_str(&self) -> Option<&str> {
        if self.is_utf8 {
            std::str::from_utf8(&self.content).ok()
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// SkillFrontmatter struct
pub struct SkillFrontmatter {
    pub name: String,
    pub description: String,
    pub vfs_path: PosixPath,
    pub tags: Vec<String>,
    pub sigstore_verified: bool,
    pub blake3_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// AsyncTaskStatus enum
pub enum AsyncTaskStatus {
    Pending,
    Running,
    InputRequired { prompt: String },
    Succeeded,
    Failed { error: String },
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// AsyncTaskHandle struct
pub struct AsyncTaskHandle {
    pub task_id: TaskId,
    pub subagent_name: String,
    pub transport_scheme: String,
    pub endpoint: String,
    pub thread_id: String,
    pub run_id: String,
    pub child_svid_spiffe_id: String,
    pub status: AsyncTaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// RubricOutcome enum
pub enum RubricOutcome {
    Satisfied,
    Failed { feedback: String },
    MaxIterationsReached { iterations: u32 },
    GraderError { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// SubagentMode enum
pub enum SubagentMode {
    Isolated,
    Fork,
}
