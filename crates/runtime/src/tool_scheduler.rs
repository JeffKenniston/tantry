use std::collections::VecDeque;

use base::ast::ToolCallId;
use base::path::{validate_and_normalize_path, PosixPath};
use base::tools_meta::{classify_tool_access, ToolAccessFootprint};

/// A single `ContentBlock::ToolUse` invocation extracted from an assistant message,
/// tagged with its 0-based `original_index` so `ToolResult` messages are reassembled
/// in strict `1..=M` declaration order after concurrent wave execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledToolCall {
    pub original_index: usize,
    pub id: ToolCallId,
    pub name: String,
    pub input: serde_json::Value,
}

/// Directed conflict graph over a batch of `ScheduledToolCall` items.
#[derive(Debug, Clone)]
pub struct BernsteinConflictDag {
    pub nodes: Vec<ScheduledToolCall>,
    pub footprints: Vec<ToolAccessFootprint>,
    pub adj: Vec<Vec<usize>>,
    pub in_degree: Vec<usize>,
}

/// 22-Tool Bernstein Dependency-DAG Scheduler.
///
/// Partitions a sequence of `ScheduledToolCall` invocations into conflict-free
/// topological waves using Kahn's level-order algorithm.
#[derive(Debug, Clone, Default)]
pub struct BernsteinToolScheduler;

impl BernsteinToolScheduler {
    pub fn new() -> Self {
        Self
    }

    /// Extracts the read/write footprint $(\mathcal{R}_i, \mathcal{W}_i)$ for a tool call,
    /// including virtual metadata namespaces (`/__meta__/todos`, `/__meta__/memory`,
    /// `/__meta__/async_tasks`, `/__meta__/tunnel`) and global barriers (`/**`).
    pub fn classify_call(call: &ScheduledToolCall) -> ToolAccessFootprint {
        let mut footprint = classify_tool_access(&call.name, &call.input);

        // Ensure path-bearing tools have normalized POSIX paths if not already populated.
        if footprint.reads.is_empty() && footprint.writes.is_empty() && !footprint.is_global_barrier
        {
            match call.name.as_str() {
                "write_todos" => {
                    let meta = PosixPath::new_unchecked("/__meta__/todos");
                    footprint.reads.push(meta.clone());
                    footprint.writes.push(meta);
                }
                "read_todos" => {
                    footprint
                        .reads
                        .push(PosixPath::new_unchecked("/__meta__/todos"));
                }
                "update_memory" => {
                    let meta = PosixPath::new_unchecked("/__meta__/memory");
                    footprint.reads.push(meta.clone());
                    footprint.writes.push(meta);
                    if let Some(raw) = call.input.get("path").and_then(|v| v.as_str()) {
                        if let Ok(norm) = validate_and_normalize_path(raw) {
                            footprint.reads.push(norm.clone());
                            footprint.writes.push(norm);
                        }
                    } else {
                        let default_mem = PosixPath::new_unchecked("/memories/AGENTS.md");
                        footprint.reads.push(default_mem.clone());
                        footprint.writes.push(default_mem);
                    }
                }
                "launch_async_task" | "update_async_task" | "cancel_async_task" => {
                    let meta = PosixPath::new_unchecked("/__meta__/async_tasks");
                    footprint.reads.push(meta.clone());
                    footprint.writes.push(meta);
                }
                "check_async_task" | "list_async_tasks" => {
                    footprint
                        .reads
                        .push(PosixPath::new_unchecked("/__meta__/async_tasks"));
                }
                "ephemeral_tunnel" => {
                    let meta = PosixPath::new_unchecked("/__meta__/tunnel");
                    footprint.reads.push(meta.clone());
                    footprint.writes.push(meta);
                }
                "read_file" | "ls" => {
                    let p = call
                        .input
                        .get("path")
                        .and_then(|v| v.as_str())
                        .and_then(|raw| validate_and_normalize_path(raw).ok())
                        .unwrap_or_else(|| PosixPath::new_unchecked("/**"));
                    footprint.reads.push(p);
                }
                "write_file" | "edit_file" | "delete" => {
                    let p = call
                        .input
                        .get("path")
                        .and_then(|v| v.as_str())
                        .and_then(|raw| validate_and_normalize_path(raw).ok())
                        .unwrap_or_else(|| PosixPath::new_unchecked("/**"));
                    footprint.reads.push(p.clone());
                    footprint.writes.push(p);
                    footprint.is_mutating_for_semantic_cache = true;
                }
                "glob" | "grep" | "ast_blast_radius" | "repo_map" => {
                    footprint.reads.push(PosixPath::new_unchecked("/**"));
                }
                "execute" | "eval" | "browser" | "computer" | "task" => {
                    let all = PosixPath::new_unchecked("/**");
                    footprint.reads.push(all.clone());
                    footprint.writes.push(all);
                    footprint.is_global_barrier = true;
                    footprint.is_mutating_for_semantic_cache = true;
                }
                _ => {
                    // Unknown / custom tool defaults to a conservative global barrier.
                    let all = PosixPath::new_unchecked("/**");
                    footprint.reads.push(all.clone());
                    footprint.writes.push(all);
                    footprint.is_global_barrier = true;
                }
            }
        }

        footprint
    }

    /// Checks whether two POSIX / virtual metadata paths intersect via exact match,
    /// global wildcard (`/**` or `/`), or directory prefix containment (`/src` vs `/src/lib.rs`).
    pub fn paths_intersect(a: &str, b: &str) -> bool {
        let a_clean = a.strip_suffix("/**").unwrap_or(a);
        let b_clean = b.strip_suffix("/**").unwrap_or(b);

        if a == "/**" || b == "/**" || a_clean == "/" || b_clean == "/" || a_clean.is_empty() || b_clean.is_empty() {
            return true;
        }

        if a_clean == b_clean {
            return true;
        }

        // Prefix containment on path segment boundary (e.g., `/src` contains `/src/lib.rs`,
        // but `/src` does NOT contain `/src_other/lib.rs`).
        if let Some(rest) = b_clean.strip_prefix(a_clean) {
            if rest.starts_with('/') {
                return true;
            }
        }
        if let Some(rest) = a_clean.strip_prefix(b_clean) {
            if rest.starts_with('/') {
                return true;
            }
        }

        false
    }

    /// Checks whether two path sets $\mathcal{A}$ and $\mathcal{B}$ have a non-empty intersection.
    pub fn sets_intersect(set_a: &[PosixPath], set_b: &[PosixPath]) -> bool {
        for a in set_a {
            for b in set_b {
                if Self::paths_intersect(a.as_str(), b.as_str()) {
                    return true;
                }
            }
        }
        false
    }

    /// Evaluates Bernstein's conflict condition between tool $i$ and tool $j$ ($i < j$):
    /// $$(\mathcal{W}_i \cap \mathcal{W}_j \neq \emptyset) \lor (\mathcal{R}_i \cap \mathcal{W}_j \neq \emptyset) \lor (\mathcal{W}_i \cap \mathcal{R}_j \neq \emptyset)$$
    pub fn footprints_conflict(fp_i: &ToolAccessFootprint, fp_j: &ToolAccessFootprint) -> bool {
        if fp_i.is_global_barrier || fp_j.is_global_barrier {
            return true;
        }

        // WAW: W_i ∩ W_j != ∅
        if Self::sets_intersect(&fp_i.writes, &fp_j.writes) {
            return true;
        }
        // WAR: R_i ∩ W_j != ∅
        if Self::sets_intersect(&fp_i.reads, &fp_j.writes) {
            return true;
        }
        // RAW: W_i ∩ R_j != ∅
        if Self::sets_intersect(&fp_i.writes, &fp_j.reads) {
            return true;
        }

        false
    }

    /// Constructs the directed conflict DAG for calls $1 \dots M$.
    pub fn build_conflict_dag(&self, calls: &[ScheduledToolCall]) -> BernsteinConflictDag {
        let m = calls.len();
        let footprints: Vec<ToolAccessFootprint> =
            calls.iter().map(Self::classify_call).collect();
        let mut adj = vec![Vec::new(); m];
        let mut in_degree = vec![0usize; m];

        for i in 0..m {
            for j in (i + 1)..m {
                if Self::footprints_conflict(&footprints[i], &footprints[j]) {
                    adj[i].push(j);
                    in_degree[j] += 1;
                }
            }
        }

        BernsteinConflictDag {
            nodes: calls.to_vec(),
            footprints,
            adj,
            in_degree,
        }
    }

    /// Partitions `calls` into conflict-free topological waves using Kahn's level-order algorithm.
    /// Every wave is guaranteed to have zero internal RAW, WAR, or WAW conflicts.
    pub fn schedule_waves(&self, calls: &[ScheduledToolCall]) -> Vec<Vec<ScheduledToolCall>> {
        if calls.is_empty() {
            return Vec::new();
        }

        let mut dag = self.build_conflict_dag(calls);
        let mut current_wave_indices: VecDeque<usize> = dag
            .in_degree
            .iter()
            .enumerate()
            .filter_map(|(idx, &deg)| if deg == 0 { Some(idx) } else { None })
            .collect();

        let mut waves: Vec<Vec<ScheduledToolCall>> = Vec::new();

        while !current_wave_indices.is_empty() {
            let wave_len = current_wave_indices.len();
            let mut wave_calls = Vec::with_capacity(wave_len);
            let mut next_wave_indices = Vec::new();

            for _ in 0..wave_len {
                if let Some(u) = current_wave_indices.pop_front() {
                    wave_calls.push(dag.nodes[u].clone());
                    for &v in &dag.adj[u] {
                        dag.in_degree[v] -= 1;
                        if dag.in_degree[v] == 0 {
                            next_wave_indices.push(v);
                        }
                    }
                }
            }

            // Keep deterministic ascending declaration order inside each wave.
            next_wave_indices.sort_unstable();
            for idx in next_wave_indices {
                current_wave_indices.push_back(idx);
            }

            waves.push(wave_calls);
        }

        waves
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_bernstein_disjoint_writes_run_in_single_wave_and_overlapping_serialize() {
        let scheduler = BernsteinToolScheduler::new();
        let calls = vec![
            ScheduledToolCall {
                original_index: 0,
                id: "call-1".to_string(),
                name: "write_file".to_string(),
                input: json!({"path": "/src/a.rs", "content": "pub fn a() {}"}),
            },
            ScheduledToolCall {
                original_index: 1,
                id: "call-2".to_string(),
                name: "write_file".to_string(),
                input: json!({"path": "/src/b.rs", "content": "pub fn b() {}"}),
            },
            ScheduledToolCall {
                original_index: 2,
                id: "call-3".to_string(),
                name: "edit_file".to_string(),
                input: json!({"path": "/src/a.rs", "old_string": "a", "new_string": "a2"}),
            },
        ];

        let waves = scheduler.schedule_waves(&calls);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0].len(), 2);
        assert_eq!(waves[0][0].id, "call-1");
        assert_eq!(waves[0][1].id, "call-2");
        assert_eq!(waves[1].len(), 1);
        assert_eq!(waves[1][0].id, "call-3");
    }

    #[test]
    fn test_virtual_meta_namespaces_and_global_barriers_serialize() {
        let scheduler = BernsteinToolScheduler::new();
        let calls = vec![
            ScheduledToolCall {
                original_index: 0,
                id: "t1".to_string(),
                name: "write_todos".to_string(),
                input: json!({"todos": []}),
            },
            ScheduledToolCall {
                original_index: 1,
                id: "t2".to_string(),
                name: "read_todos".to_string(),
                input: json!({}),
            },
            ScheduledToolCall {
                original_index: 2,
                id: "t3".to_string(),
                name: "execute".to_string(),
                input: json!({"command": "cargo", "args": ["check"]}),
            },
        ];

        let waves = scheduler.schedule_waves(&calls);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0][0].id, "t1");
        assert_eq!(waves[1][0].id, "t2");
        assert_eq!(waves[2][0].id, "t3");
    }
}