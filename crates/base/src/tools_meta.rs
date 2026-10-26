use std::collections::HashMap;
use chrono::{DateTime, Utc};
use crate::vfs_tree::VfsTree;
use crate::path::PosixPath;
use crate::ast::FileData;
use bytes::Bytes;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct ToolAccessFootprint {
    pub reads: Vec<PosixPath>,
    pub writes: Vec<PosixPath>,
    pub is_global_barrier: bool,
    pub is_mutating_for_semantic_cache: bool,
}

pub fn get_tool_footprint(tool_name: &str) -> Option<ToolAccessFootprint> {
    static CATALOG: OnceLock<HashMap<&'static str, ToolAccessFootprint>> = OnceLock::new();
    let catalog = CATALOG.get_or_init(|| {
        let mut m = HashMap::new();

        // Slot 2: Task ledger
        m.insert("write_todos", ToolAccessFootprint {
            reads: vec!["/__meta__/todos".to_string()],
            writes: vec!["/__meta__/todos".to_string()],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: false,
        });
        m.insert("read_todos", ToolAccessFootprint {
            reads: vec!["/__meta__/todos".to_string()],
            writes: vec![],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: false,
        });

        // Slot 3: Semantic skills
        m.insert("read_skills", ToolAccessFootprint {
            reads: vec!["/__meta__/skills".to_string()],
            writes: vec![],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: false,
        });

        // Slot 4: Shared Memory
        m.insert("write_memory", ToolAccessFootprint {
            reads: vec!["/__meta__/memory".to_string()],
            writes: vec!["/__meta__/memory".to_string()],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: false,
        });
        m.insert("read_memory", ToolAccessFootprint {
            reads: vec!["/__meta__/memory".to_string()],
            writes: vec![],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: false,
        });

        // Slot 5: Codebase & Files (22-tool subset)
        m.insert("read_file", ToolAccessFootprint {
            reads: vec!["/**".to_string()], // over-approximation for now
            writes: vec![],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: false,
        });
        m.insert("write_file", ToolAccessFootprint {
            reads: vec!["/**".to_string()],
            writes: vec!["/**".to_string()],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: true,
        });
        m.insert("edit_file", ToolAccessFootprint {
            reads: vec!["/**".to_string()],
            writes: vec!["/**".to_string()],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: true,
        });
        m.insert("delete", ToolAccessFootprint {
            reads: vec!["/**".to_string()],
            writes: vec!["/**".to_string()],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: true,
        });
        m.insert("list_files", ToolAccessFootprint {
            reads: vec!["/**".to_string()],
            writes: vec![],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: false,
        });

        // Slot 7: Environment & execution
        m.insert("execute", ToolAccessFootprint {
            reads: vec!["/**".to_string()],
            writes: vec!["/**".to_string()],
            is_global_barrier: true,
            is_mutating_for_semantic_cache: true,
        });
        m.insert("eval", ToolAccessFootprint {
            reads: vec!["/**".to_string()],
            writes: vec!["/**".to_string()],
            is_global_barrier: true,
            is_mutating_for_semantic_cache: true,
        });
        m.insert("browser", ToolAccessFootprint {
            reads: vec!["/**".to_string()],
            writes: vec!["/**".to_string()],
            is_global_barrier: true,
            is_mutating_for_semantic_cache: true,
        });
        m.insert("computer", ToolAccessFootprint {
            reads: vec!["/**".to_string()],
            writes: vec!["/**".to_string()],
            is_global_barrier: true,
            is_mutating_for_semantic_cache: true,
        });

        // Slot 8: Subagents
        m.insert("spawn_subagent", ToolAccessFootprint {
            reads: vec!["/**".to_string()],
            writes: vec!["/__meta__/async_tasks".to_string()],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: false,
        });
        m.insert("await_subagent", ToolAccessFootprint {
            reads: vec!["/__meta__/async_tasks".to_string()],
            writes: vec!["/__meta__/async_tasks".to_string()],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: false,
        });

        // Slot 14: Tunnel/Rubric
        m.insert("tunnel", ToolAccessFootprint {
            reads: vec!["/__meta__/tunnel".to_string()],
            writes: vec!["/__meta__/tunnel".to_string()],
            is_global_barrier: false,
            is_mutating_for_semantic_cache: false,
        });

        // Meta/Control tools (often global barriers or special cases)
        m.insert("task", ToolAccessFootprint {
            reads: vec!["/**".to_string()],
            writes: vec!["/**".to_string()],
            is_global_barrier: true,
            is_mutating_for_semantic_cache: true,
        });

        m
    });

    catalog.get(tool_name).cloned()
}

pub fn maybe_offload_tool_output(tool_use_id: &str, raw_output: &str, vfs: &mut VfsTree, now: DateTime<Utc>) -> String {
    let line_count = raw_output.lines().count();
    let char_count = raw_output.len();

    if char_count <= 20_000 && line_count <= 500 {
        return raw_output.to_string();
    }

    let path = format!("/offloaded_tool_results/{}.txt", tool_use_id);
    vfs.insert(&path, FileData {
        content: Bytes::from(raw_output.to_string()),
        blake3_hash: blake3::hash(raw_output.as_bytes()).into(),
        is_utf8: true,
        mime_type: "text/plain".to_string(),
        created_at: now,
        modified_at: now,
    });

    let lines: Vec<&str> = raw_output.lines().collect();
    let top_lines = lines.iter().take(15).cloned().collect::<Vec<&str>>().join("\n");
    let bottom_lines = if lines.len() > 15 {
        lines.iter().skip(lines.len() - 15).cloned().collect::<Vec<&str>>().join("\n")
    } else {
        String::new()
    };

    let diagnostic_keywords = ["error[E", "error:", "FAILED", "panicked at", "Traceback", "SyntaxError", "Exception"];
    let mut diagnostics = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        for kw in &diagnostic_keywords {
            if line.contains(kw) {
                diagnostics.push(format!("{}: {}", i + 1, line));
                break;
            }
        }
        if diagnostics.len() >= 10 {
            break;
        }
    }

    let diagnostics_str = if diagnostics.is_empty() {
        "None found.".to_string()
    } else {
        diagnostics.join("\n")
    };

    format!(
        "Output truncated. Full output saved to VFS path: {}\n\
        Total characters: {}, Total lines: {}\n\
        \n\
        --- Top 15 lines ---\n\
        {}\n\
        \n\
        --- Bottom 15 lines ---\n\
        {}\n\
        \n\
        --- Prioritized Diagnostics (up to 10) ---\n\
        {}",
        path, char_count, line_count, top_lines, bottom_lines, diagnostics_str
    )
}
