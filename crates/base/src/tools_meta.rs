use crate::ast::FileData;
use crate::path::PosixPath;
use crate::vfs::VfsTree;
use chrono::{DateTime, Utc};
use std::sync::Arc;

pub const TOOL_WRITE_TODOS: &str = "write_todos";
pub const TOOL_READ_TODOS: &str = "read_todos";

pub const TOOL_LS: &str = "ls";
pub const TOOL_READ_FILE: &str = "read_file";
pub const TOOL_WRITE_FILE: &str = "write_file";
pub const TOOL_EDIT_FILE: &str = "edit_file";
pub const TOOL_DELETE: &str = "delete";
pub const TOOL_GLOB: &str = "glob";
pub const TOOL_GREP: &str = "grep";
pub const TOOL_EXECUTE: &str = "execute";

pub const TOOL_AST_BLAST_RADIUS: &str = "ast_blast_radius";
pub const TOOL_REPO_MAP: &str = "repo_map";

pub const TOOL_EVAL: &str = "eval";
pub const TOOL_BROWSER: &str = "browser";
pub const TOOL_COMPUTER: &str = "computer";
pub const TOOL_EPHEMERAL_TUNNEL: &str = "ephemeral_tunnel";

pub const TOOL_TASK: &str = "task";

pub const TOOL_LAUNCH_ASYNC_TASK: &str = "launch_async_task";
pub const TOOL_CHECK_ASYNC_TASK: &str = "check_async_task";
pub const TOOL_UPDATE_ASYNC_TASK: &str = "update_async_task";
pub const TOOL_CANCEL_ASYNC_TASK: &str = "cancel_async_task";
pub const TOOL_LIST_ASYNC_TASKS: &str = "list_async_tasks";

pub const TOOL_UPDATE_MEMORY: &str = "update_memory";

#[derive(Debug, Clone, PartialEq)]
pub struct ToolAccessFootprint {
    pub reads: Vec<PosixPath>,
    pub writes: Vec<PosixPath>,
    pub is_global_barrier: bool,
    pub is_mutating_for_semantic_cache: bool,
}

impl ToolAccessFootprint {
    pub fn for_tool(name: &str, path_arg: Option<PosixPath>) -> Self {
        let empty = vec![];
        match name {
            TOOL_WRITE_TODOS => Self {
                reads: vec!["/__meta__/todos".to_string()],
                writes: vec!["/__meta__/todos".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_READ_TODOS => Self {
                reads: vec!["/__meta__/todos".to_string()],
                writes: empty.clone(),
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
                writes: empty.clone(),
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_EPHEMERAL_TUNNEL => Self {
                reads: vec!["/__meta__/tunnel".to_string()],
                writes: vec!["/__meta__/tunnel".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_READ_FILE | TOOL_LS => {
                let p = path_arg.unwrap_or_else(|| "/**".to_string());
                Self {
                    reads: vec![p],
                    writes: empty.clone(),
                    is_global_barrier: false,
                    is_mutating_for_semantic_cache: false,
                }
            }
            TOOL_GLOB | TOOL_GREP | TOOL_AST_BLAST_RADIUS | TOOL_REPO_MAP => Self {
                reads: vec!["/**".to_string()],
                writes: empty.clone(),
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
            TOOL_WRITE_FILE | TOOL_EDIT_FILE | TOOL_DELETE => {
                let p = path_arg.unwrap_or_else(|| "/**".to_string());
                Self {
                    reads: vec![p.clone()],
                    writes: vec![p],
                    is_global_barrier: false,
                    is_mutating_for_semantic_cache: true,
                }
            }
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

pub fn maybe_offload_tool_output(
    tool_use_id: &str,
    raw_output: &str,
    vfs: &mut VfsTree,
    now: DateTime<Utc>,
) -> String {
    let char_count = raw_output.len();
    let line_count = raw_output.lines().count();

    if char_count <= 20_000 && line_count <= 500 {
        return raw_output.to_string();
    }

    let offloaded_path = format!("/offloaded_tool_results/{}.txt", tool_use_id);
    let file_data = Arc::new(FileData::new_utf8(raw_output.to_string(), now));
    let _ = vfs.insert(offloaded_path.clone(), file_data);

    let lines: Vec<&str> = raw_output.lines().collect();
    let first_15: Vec<&str> = lines.iter().take(15).copied().collect();
    let last_15: Vec<&str> = if lines.len() > 15 {
        lines.iter().skip(lines.len() - 15).copied().collect()
    } else {
        vec![]
    };

    let diagnostic_markers = [
        "error[E",
        "error:",
        "FAILED",
        "panicked at",
        "Traceback",
        "SyntaxError",
        "Exception",
    ];

    let mut diagnostics = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        for marker in &diagnostic_markers {
            if line.contains(marker) {
                diagnostics.push(format!("{}: {}", idx + 1, line));
                break;
            }
        }
        if diagnostics.len() >= 10 {
            break;
        }
    }

    let mut summary = String::new();
    summary.push_str(&format!("Output offloaded to VFS: {}\n", offloaded_path));
    summary.push_str(&format!(
        "Total characters: {}, Total lines: {}\n\n",
        char_count, line_count
    ));

    summary.push_str("--- First 15 lines ---\n");
    summary.push_str(&first_15.join("\n"));
    summary.push_str("\n\n");

    if !diagnostics.is_empty() {
        summary.push_str("--- High-Priority Diagnostics ---\n");
        summary.push_str(&diagnostics.join("\n"));
        summary.push_str("\n\n");
    }

    summary.push_str("--- Last 15 lines ---\n");
    summary.push_str(&last_15.join("\n"));
    summary.push('\n');

    summary
}
