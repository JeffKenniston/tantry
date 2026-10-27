use crate::ast::FileData;
use crate::path::PosixPath;
use crate::vfs_tree::VfsTree;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use serde_json::Value;

/// TOOL_WRITE_TODOS const
pub const TOOL_WRITE_TODOS: &str = "write_todos";
/// TOOL_READ_TODOS const
pub const TOOL_READ_TODOS: &str = "read_todos";
/// TOOL_LS const
pub const TOOL_LS: &str = "ls";
/// TOOL_READ_FILE const
pub const TOOL_READ_FILE: &str = "read_file";
/// TOOL_WRITE_FILE const
pub const TOOL_WRITE_FILE: &str = "write_file";
/// TOOL_EDIT_FILE const
pub const TOOL_EDIT_FILE: &str = "edit_file";
/// TOOL_DELETE const
pub const TOOL_DELETE: &str = "delete";
/// TOOL_GLOB const
pub const TOOL_GLOB: &str = "glob";
/// TOOL_GREP const
pub const TOOL_GREP: &str = "grep";
/// TOOL_EXECUTE const
pub const TOOL_EXECUTE: &str = "execute";
/// TOOL_AST_BLAST_RADIUS const
pub const TOOL_AST_BLAST_RADIUS: &str = "ast_blast_radius";
/// TOOL_REPO_MAP const
pub const TOOL_REPO_MAP: &str = "repo_map";
/// TOOL_EVAL const
pub const TOOL_EVAL: &str = "eval";
/// TOOL_BROWSER const
pub const TOOL_BROWSER: &str = "browser";
/// TOOL_COMPUTER const
pub const TOOL_COMPUTER: &str = "computer";
/// TOOL_EPHEMERAL_TUNNEL const
pub const TOOL_EPHEMERAL_TUNNEL: &str = "ephemeral_tunnel";
/// TOOL_TASK const
pub const TOOL_TASK: &str = "task";
/// TOOL_LAUNCH_ASYNC_TASK const
pub const TOOL_LAUNCH_ASYNC_TASK: &str = "launch_async_task";
/// TOOL_CHECK_ASYNC_TASK const
pub const TOOL_CHECK_ASYNC_TASK: &str = "check_async_task";
/// TOOL_UPDATE_ASYNC_TASK const
pub const TOOL_UPDATE_ASYNC_TASK: &str = "update_async_task";
/// TOOL_CANCEL_ASYNC_TASK const
pub const TOOL_CANCEL_ASYNC_TASK: &str = "cancel_async_task";
/// TOOL_LIST_ASYNC_TASKS const
pub const TOOL_LIST_ASYNC_TASKS: &str = "list_async_tasks";
/// TOOL_UPDATE_MEMORY const
pub const TOOL_UPDATE_MEMORY: &str = "update_memory";

#[derive(Debug, Clone, PartialEq)]
/// ToolAccessFootprint struct
pub struct ToolAccessFootprint {
    pub reads: Vec<PosixPath>,
    pub writes: Vec<PosixPath>,
    pub is_global_barrier: bool,
    pub is_mutating_for_semantic_cache: bool,
}

impl ToolAccessFootprint {
    /// for_tool fn
    pub fn for_tool(name: &str, path_arg: Option<PosixPath>) -> Self {
        match name {
            TOOL_WRITE_TODOS => Self {
                reads: vec!["/__meta__/todos".to_string()],
                writes: vec!["/__meta__/todos".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_READ_TODOS => Self {
                reads: vec!["/__meta__/todos".to_string()],
                writes: vec![],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_UPDATE_MEMORY => Self {
                reads: vec!["/__meta__/memory".to_string()],
                writes: vec!["/__meta__/memory".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_LAUNCH_ASYNC_TASK | TOOL_UPDATE_ASYNC_TASK | TOOL_CANCEL_ASYNC_TASK => Self {
                reads: vec!["/__meta__/async_tasks".to_string()],
                writes: vec!["/__meta__/async_tasks".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_CHECK_ASYNC_TASK | TOOL_LIST_ASYNC_TASKS => Self {
                reads: vec!["/__meta__/async_tasks".to_string()],
                writes: vec![],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_EPHEMERAL_TUNNEL => Self {
                reads: vec!["/__meta__/tunnel".to_string()],
                writes: vec!["/__meta__/tunnel".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_READ_FILE | TOOL_LS => Self {
                reads: path_arg.map(|p| vec![p]).unwrap_or_default(),
                writes: vec![],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_GLOB | TOOL_GREP | TOOL_AST_BLAST_RADIUS | TOOL_REPO_MAP => Self {
                reads: vec!["/**".to_string()],
                writes: vec![],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_WRITE_FILE | TOOL_EDIT_FILE | TOOL_DELETE => Self {
                reads: path_arg.clone().map(|p| vec![p]).unwrap_or_default(),
                writes: path_arg.map(|p| vec![p]).unwrap_or_default(),
                is_global_barrier: false,
                is_mutating_for_semantic_cache: true,
            },
            TOOL_EXECUTE | TOOL_EVAL | TOOL_BROWSER | TOOL_COMPUTER | TOOL_TASK => Self {
                reads: vec!["/**".to_string()],
                writes: vec!["/**".to_string()],
                is_global_barrier: true,
                is_mutating_for_semantic_cache: true,
            },
            _ => Self {
                reads: vec!["/**".to_string()],
                writes: vec!["/**".to_string()],
                is_global_barrier: true,
                is_mutating_for_semantic_cache: true,
            },
        }
    }
}

pub fn classify_tool_footprint(tool_name: &str, input: &Value) -> ToolAccessFootprint {
    let path_arg = input
        .get("path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    ToolAccessFootprint::for_tool(tool_name, path_arg)
}

/// maybe_offload_tool_output fn
pub fn maybe_offload_tool_output(
    tool_use_id: &str,
    raw_output: &str,
    vfs: &mut VfsTree,
    now: DateTime<Utc>,
) -> String {
    let char_count = raw_output.len();
    let lines: Vec<&str> = raw_output.lines().collect();
    let line_count = lines.len();

    if char_count <= 20_000 && line_count <= 500 {
        return raw_output.to_string();
    }

    let offload_path = format!("/offloaded_tool_results/{}.txt", tool_use_id);
    let _ = vfs.insert(
        offload_path.clone(),
        Arc::new(FileData::new_utf8(raw_output.to_string(), now)),
    );

    let first_15: Vec<&str> = lines.iter().take(15).copied().collect();
    let last_15: Vec<&str> = if line_count > 15 {
        lines.iter().skip(line_count - 15).copied().collect()
    } else {
        vec![]
    };

    let mut diagnostics = Vec::new();
    let keywords = [
        "error[E",
        "error:",
        "FAILED",
        "panicked at",
        "Traceback",
        "SyntaxError",
        "Exception",
    ];

    for (i, line) in lines.iter().enumerate() {
        if keywords.iter().any(|k| line.contains(k)) {
            diagnostics.push(format!("{}: {}", i + 1, line));
            if diagnostics.len() == 10 {
                break;
            }
        }
    }

    let mut summary = String::new();
    summary.push_str(&format!(
        "Output offloaded to {}. Total length: {} chars, {} lines.\n",
        offload_path, char_count, line_count
    ));

    summary.push_str("--- First 15 lines ---\n");
    summary.push_str(&first_15.join("\n"));
    summary.push('\n');

    if !last_15.is_empty() {
        summary.push_str("--- Last 15 lines ---\n");
        summary.push_str(&last_15.join("\n"));
        summary.push('\n');
    }

    if !diagnostics.is_empty() {
        summary.push_str("--- Highest-priority diagnostics ---\n");
        summary.push_str(&diagnostics.join("\n"));
        summary.push('\n');
    }

    summary
}
