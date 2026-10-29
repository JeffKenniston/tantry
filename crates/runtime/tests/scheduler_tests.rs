use base::tools_meta::ToolAccessFootprint;
use runtime::tool_scheduler::{BernsteinToolScheduler, ToolUseCall};
use serde_json::json;

#[test]
fn test_disjoint_file_writes() {
    let calls = vec![
        ToolUseCall {
            tool_use_id: "t1".to_string(),
            tool_name: "write_file".to_string(),
            tool_input: json!({"path": "/src/a.rs"}),
            footprint: ToolAccessFootprint {
                reads: vec![],
                writes: vec!["/src/a.rs".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: true,
            },
        },
        ToolUseCall {
            tool_use_id: "t2".to_string(),
            tool_name: "write_file".to_string(),
            tool_input: json!({"path": "/src/b.rs"}),
            footprint: ToolAccessFootprint {
                reads: vec![],
                writes: vec!["/src/b.rs".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: true,
            },
        },
    ];
    let waves = BernsteinToolScheduler::partition_into_waves(&calls);
    assert_eq!(waves, vec![vec![0, 1]]);
}

#[test]
fn test_overlapping_file_writes() {
    let calls = vec![
        ToolUseCall {
            tool_use_id: "t1".to_string(),
            tool_name: "write_file".to_string(),
            tool_input: json!({"path": "/src/a.rs"}),
            footprint: ToolAccessFootprint {
                reads: vec![],
                writes: vec!["/src/a.rs".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: true,
            },
        },
        ToolUseCall {
            tool_use_id: "t2".to_string(),
            tool_name: "write_file".to_string(),
            tool_input: json!({"path": "/src/a.rs"}),
            footprint: ToolAccessFootprint {
                reads: vec![],
                writes: vec!["/src/a.rs".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: true,
            },
        },
    ];
    let waves = BernsteinToolScheduler::partition_into_waves(&calls);
    assert_eq!(waves, vec![vec![0], vec![1]]);
}

#[test]
fn test_todos_conflicts() {
    let calls = vec![
        ToolUseCall {
            tool_use_id: "t1".to_string(),
            tool_name: "plan_step_complete".to_string(),
            tool_input: json!({}),
            footprint: ToolAccessFootprint {
                reads: vec![],
                writes: vec!["/__meta__/todos".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: true,
            },
        },
        ToolUseCall {
            tool_use_id: "t2".to_string(),
            tool_name: "set_plan".to_string(),
            tool_input: json!({}),
            footprint: ToolAccessFootprint {
                reads: vec![],
                writes: vec!["/__meta__/todos".to_string()],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: true,
            },
        },
    ];
    let waves = BernsteinToolScheduler::partition_into_waves(&calls);
    assert_eq!(waves, vec![vec![0], vec![1]]);
}

#[test]
fn test_global_barrier() {
    let calls = vec![
        ToolUseCall {
            tool_use_id: "t1".to_string(),
            tool_name: "read_file".to_string(),
            tool_input: json!({"path": "/src/a.rs"}),
            footprint: ToolAccessFootprint {
                reads: vec!["/src/a.rs".to_string()],
                writes: vec![],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
        },
        ToolUseCall {
            tool_use_id: "t2".to_string(),
            tool_name: "bash".to_string(),
            tool_input: json!({"command": "cargo test"}),
            footprint: ToolAccessFootprint {
                reads: vec!["/**".to_string()],
                writes: vec!["/**".to_string()],
                is_global_barrier: true,
                is_mutating_for_semantic_cache: true,
            },
        },
        ToolUseCall {
            tool_use_id: "t3".to_string(),
            tool_name: "read_file".to_string(),
            tool_input: json!({"path": "/src/b.rs"}),
            footprint: ToolAccessFootprint {
                reads: vec!["/src/b.rs".to_string()],
                writes: vec![],
                is_global_barrier: false,
                is_mutating_for_semantic_cache: false,
            },
        },
    ];
    let waves = BernsteinToolScheduler::partition_into_waves(&calls);
    assert_eq!(waves, vec![vec![0], vec![1], vec![2]]);
}
