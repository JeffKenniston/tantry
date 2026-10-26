use bytes::Bytes;
use std::collections::BTreeMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

pub type MessageId = Uuid;
pub type ToolCallId = String;
pub type TaskId = String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheControl {
    Ephemeral,
    Persistent { ttl_seconds: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaKind {
    Image,
    Video,
    Audio,
    Document,
}

impl MediaKind {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "jpg" | "jpeg" | "png" | "gif" | "webp" => Some(Self::Image),
            "mp4" | "webm" | "mov" => Some(Self::Video),
            "mp3" | "wav" | "ogg" => Some(Self::Audio),
            "pdf" | "doc" | "docx" | "txt" => Some(Self::Document),
            _ => None,
        }
    }

    pub fn from_mime(mime: &str) -> Option<Self> {
        if mime.starts_with("image/") {
            Some(Self::Image)
        } else if mime.starts_with("video/") {
            Some(Self::Video)
        } else if mime.starts_with("audio/") {
            Some(Self::Audio)
        } else if mime.starts_with("application/pdf") || mime.starts_with("text/") {
            Some(Self::Document)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExecuteArtifact {
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlastRadiusReport {
    pub files_touched: usize,
    pub lines_added: usize,
    pub lines_removed: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ToolArtifact {
    Execute(ExecuteArtifact),
    BlastRadius(BlastRadiusReport),
    McpUiResource(String),
    Custom(Bytes),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContentBlock {
    Text(String),
    Reasoning(String),
    Media(Bytes, MediaKind),
    ToolUse {
        tool_call_id: ToolCallId,
        name: String,
        input: serde_json::Value, // Using BTreeMap for simplicity in stub
    },
    ToolResult {
        tool_call_id: ToolCallId,
        result: String,
        artifact: Option<ToolArtifact>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub id: MessageId,
    pub role: Role,
    pub content: Vec<ContentBlock>,
    pub created_at: DateTime<Utc>,
    pub metadata: BTreeMap<String, String>,
}

impl Message {
    pub fn user(content: Vec<ContentBlock>) -> Self {
        Self {
            id: Uuid::now_v7(),
            role: Role::User,
            content,
            created_at: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn system(content: Vec<ContentBlock>) -> Self {
        Self {
            id: Uuid::now_v7(),
            role: Role::System,
            content,
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

    pub fn tool_result(tool_call_id: ToolCallId, result: String, artifact: Option<ToolArtifact>) -> Self {
        Self {
            id: Uuid::now_v7(),
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_call_id,
                result,
                artifact,
            }],
            created_at: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn assistant_text(&self) -> String {
        if self.role != Role::Assistant {
            return String::new();
        }
        self.content.iter().filter_map(|block| {
            if let ContentBlock::Text(text) = block {
                Some(text.as_str())
            } else {
                None
            }
        }).collect::<Vec<&str>>().join("\n")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileData {
    pub content: Bytes,
    pub blake3_hash: [u8; 32],
    pub is_utf8: bool,
    pub mime_type: String,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

impl FileData {
    pub fn new_utf8(content: String, mime_type: String) -> Self {
        let bytes = Bytes::from(content);
        let hash = *blake3::hash(&bytes).as_bytes();
        let now = Utc::now();
        Self {
            content: bytes,
            blake3_hash: hash,
            is_utf8: true,
            mime_type,
            created_at: now,
            modified_at: now,
        }
    }

    pub fn new_binary(content: Bytes, mime_type: String) -> Self {
        let hash = *blake3::hash(&content).as_bytes();
        let now = Utc::now();
        // Basic UTF-8 check
        let is_utf8 = std::str::from_utf8(&content).is_ok();
        Self {
            content,
            blake3_hash: hash,
            is_utf8,
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

// Stub models
#[derive(Debug, Clone)] pub struct TodoStatus;
#[derive(Debug, Clone)] pub struct TodoItem;
#[derive(Debug, Clone)] pub struct SkillFrontmatter;
#[derive(Debug, Clone)] pub struct AsyncTaskStatus;
#[derive(Debug, Clone)] pub struct AsyncTaskHandle;
#[derive(Debug, Clone)] pub struct RubricOutcome;
#[derive(Debug, Clone)] pub enum SubagentMode { Isolated, Fork }
