use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub type MessageId = Uuid;
pub type ToolCallId = String;
pub type TaskId = String;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaKind {
    Image,
    Video,
    Audio,
    Document,
}

impl MediaKind {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "jpg" | "jpeg" | "png" | "webp" => Some(Self::Image),
            "webm" => Some(Self::Video),
            _ => None, // Expand as needed
        }
    }

    pub fn from_mime(mime: &str) -> Option<Self> {
        let mime = mime.to_lowercase();
        if mime.starts_with("image/") {
            Some(Self::Image)
        } else if mime.starts_with("video/") {
            Some(Self::Video)
        } else if mime.starts_with("audio/") {
            Some(Self::Audio)
        } else if mime.starts_with("application/") || mime.starts_with("text/") {
            Some(Self::Document)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheControl {
    Ephemeral,
    Persistent { ttl_seconds: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteArtifact {
    pub exit_code: i32,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub peak_rss_bytes: Option<u64>,
    pub sandbox_id: String,
    pub isolation_tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusReport {
    pub target_symbol: String,
    pub affected_files: Vec<String>,
    pub reverse_dependency_count: usize,
    pub max_depth_reached: usize,
    pub katz_centrality: f32,
    pub signature_mutated: bool,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolArtifact {
    Execute(ExecuteArtifact),
    BlastRadius(BlastRadiusReport),
    McpUiResource { uri: String, mime_type: String },
    Custom(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContentBlock {
    Text { text: String, cache_control: Option<CacheControl> },
    Reasoning { thought_summary: String, opaque_signature: Option<bytes::Bytes> },
    Media { kind: MediaKind, mime_type: String, data: bytes::Bytes, source_path: Option<String> },
    ToolUse { id: ToolCallId, name: String, input: serde_json::Value },
    ToolResult { tool_use_id: ToolCallId, is_error: bool, content: Vec<ContentBlock>, artifact: Option<ToolArtifact> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId,
    pub role: Role,
    pub content: Vec<ContentBlock>,
    pub created_at: DateTime<Utc>,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl Message {
    pub fn user(text: String) -> Self {
        Self {
            id: Uuid::now_v7(),
            role: Role::User,
            content: vec![ContentBlock::Text { text, cache_control: None }],
            created_at: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn system(text: String, cache_control: Option<CacheControl>) -> Self {
        Self {
            id: Uuid::now_v7(),
            role: Role::System,
            content: vec![ContentBlock::Text { text, cache_control }],
            created_at: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn assistant(content: Vec<ContentBlock>) -> Self {
        Self {
            id: Uuid::now_v7(),
            role: Role::Assistant,
            content,
            created_at: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn tool_result(tool_use_id: ToolCallId, is_error: bool, text: String, artifact: Option<ToolArtifact>) -> Self {
        Self {
            id: Uuid::now_v7(),
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id,
                is_error,
                content: vec![ContentBlock::Text { text, cache_control: None }],
                artifact,
            }],
            created_at: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn assistant_text(&self) -> Option<String> {
        if self.role != Role::Assistant {
            return None;
        }
        let texts: Vec<String> = self.content.iter().filter_map(|b| {
            if let ContentBlock::Text { text, .. } = b {
                if !text.is_empty() {
                    Some(text.clone())
                } else {
                    None
                }
            } else {
                None
            }
        }).collect();

        if texts.is_empty() {
            None
        } else {
            Some(texts.join("\n"))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TodoStatus {
    Pending,
    InProgress,
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoItem {
    pub id: String,
    pub content: String,
    pub status: TodoStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileData {
    pub content: bytes::Bytes,
    pub blake3_hash: [u8; 32],
    pub is_utf8: bool,
    pub mime_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

impl FileData {
    pub fn new_utf8(text: String, now: DateTime<Utc>) -> Self {
        let hash = blake3::hash(text.as_bytes()).into();
        Self {
            content: bytes::Bytes::from(text),
            blake3_hash: hash,
            is_utf8: true,
            mime_type: Some("text/plain; charset=utf-8".to_string()),
            created_at: now,
            modified_at: now,
        }
    }

    pub fn new_binary(bytes: bytes::Bytes, mime_type: Option<String>, now: DateTime<Utc>) -> Self {
        let hash = blake3::hash(&bytes).into();
        Self {
            content: bytes,
            blake3_hash: hash,
            is_utf8: false,
            mime_type,
            created_at: now,
            modified_at: now,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        if self.is_utf8 {
            std::str::from_utf8(&self.content).ok()
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillFrontmatter {
    pub name: String,
    pub description: String,
    pub vfs_path: String,
    pub tags: Vec<String>,
    pub sigstore_verified: bool,
    pub blake3_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AsyncTaskStatus {
    Pending,
    Running,
    InputRequired { prompt: String },
    Succeeded,
    Failed { error: String },
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RubricOutcome {
    Satisfied,
    Failed { feedback: String },
    MaxIterationsReached { iterations: u32 },
    GraderError { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubagentMode {
    Isolated,
    Fork,
}
