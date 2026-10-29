use base::ast::Message;
use base::state::TantryState;
use base::tools_meta::ToolAccessFootprint;
use chrono::Utc;
use futures::future::join_all;
use serde_json::Value;
use std::pin::Pin;

#[derive(Debug, Clone)]
pub struct ToolUseCall {
    pub tool_use_id: String,
    pub tool_name: String,
    pub tool_input: Value,
    pub footprint: ToolAccessFootprint,
}

pub fn paths_intersect(p1: &str, p2: &str) -> bool {
    if p1 == "/**" || p2 == "/**" {
        return true;
    }
    let n1 = p1.trim_end_matches('/');
    let n2 = p2.trim_end_matches('/');
    if n1.is_empty() || n2.is_empty() || n1 == n2 {
        return true;
    }
    n2.starts_with(&format!("{}/", n1)) || n1.starts_with(&format!("{}/", n2))
}

pub struct BernsteinToolScheduler;

impl BernsteinToolScheduler {
    pub fn partition_into_waves(calls: &[ToolUseCall]) -> Vec<Vec<usize>> {
        let n = calls.len();
        let mut adj = vec![vec![]; n];
        let mut in_degree = vec![0; n];

        for i in 0..n {
            for j in (i + 1)..n {
                let mut conflict = false;
                if calls[i].footprint.is_global_barrier || calls[j].footprint.is_global_barrier {
                    conflict = true;
                } else {
                    let w_i = &calls[i].footprint.writes;
                    let r_i = &calls[i].footprint.reads;
                    let w_j = &calls[j].footprint.writes;
                    let r_j = &calls[j].footprint.reads;

                    for p1 in w_i {
                        for p2 in w_j {
                            if paths_intersect(p1, p2) {
                                conflict = true;
                            }
                        }
                    }

                    for p1 in r_i {
                        for p2 in w_j {
                            if paths_intersect(p1, p2) {
                                conflict = true;
                            }
                        }
                    }

                    for p1 in w_i {
                        for p2 in r_j {
                            if paths_intersect(p1, p2) {
                                conflict = true;
                            }
                        }
                    }
                }

                if conflict {
                    adj[i].push(j);
                    in_degree[j] += 1;
                }
            }
        }

        let mut waves = Vec::new();
        let mut queue = Vec::new();

        for (i, &deg) in in_degree.iter().enumerate() {
            if deg == 0 {
                queue.push(i);
            }
        }

        while !queue.is_empty() {
            waves.push(queue.clone());
            let mut next_queue = Vec::new();

            for &u in &queue {
                for &v in &adj[u] {
                    in_degree[v] -= 1;
                    if in_degree[v] == 0 {
                        next_queue.push(v);
                    }
                }
            }

            queue = next_queue;
        }

        waves
    }

    pub async fn execute_waves<'a, F>(
        state: &'a mut TantryState,
        calls: &'a [ToolUseCall],
        _ctx: &'a crate::middleware::TurnExecutionContext,
        metrics: &'a crate::observability::RuntimeMetrics,
        tool_executor: F,
    ) -> Result<Vec<Message>, crate::error::RuntimeError>
    where
        F: Fn(
            TantryState,
            &'a ToolUseCall,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = (Result<Message, crate::error::RuntimeError>, TantryState),
                    > + Send
                    + 'a,
            >,
        >,
    {
        let waves = Self::partition_into_waves(calls);
        let mut all_messages = vec![None; calls.len()];

        for wave in waves {
            if wave.len() == 1 {
                let idx = wave[0];
                let (msg_res, new_state) = tool_executor(state.clone(), &calls[idx]).await;
                all_messages[idx] = Some(msg_res?);
                *state = new_state;
            } else {
                let base_vfs = state.files.clone();
                let mut futures = Vec::new();

                for &idx in wave.iter() {
                    let mut child_state = state.clone();
                    child_state.files = base_vfs.clone();

                    let call = &calls[idx];
                    let fut = tool_executor(child_state, call);
                    futures.push(async move {
                        let (result, new_child_state) = fut.await;
                        (idx, result, new_child_state)
                    });
                }

                let results = join_all(futures).await;
                let mut branches: Vec<(String, base::vfs_tree::VfsTree)> = Vec::new();

                for (idx, result, new_child_state) in results {
                    let msg = result?;
                    all_messages[idx] = Some(msg);

                    let has_file_writes = new_child_state.files.root_hash() != base_vfs.root_hash()
                        || calls[idx]
                            .footprint
                            .writes
                            .iter()
                            .any(|p| !p.starts_with("/__meta__/"));

                    if has_file_writes {
                        branches.push((
                            format!("tool_{}_{}", calls[idx].tool_name, calls[idx].tool_use_id),
                            new_child_state.files.clone(),
                        ));
                    }

                    if calls[idx]
                        .footprint
                        .writes
                        .iter()
                        .any(|p| p == "/__meta__/todos")
                    {
                        state.todos = new_child_state.todos;
                    }
                    if calls[idx]
                        .footprint
                        .writes
                        .iter()
                        .any(|p| p == "/__meta__/memory")
                    {
                        state.memory_contents = new_child_state.memory_contents;
                    }
                    if calls[idx]
                        .footprint
                        .writes
                        .iter()
                        .any(|p| p == "/__meta__/async_tasks")
                    {
                        state.async_tasks = new_child_state.async_tasks;
                    }
                }

                if !branches.is_empty() {
                    let report =
                        backends::merge::merge_subagent_trees(&base_vfs, branches, Utc::now());
                    state.files = report.merged_tree;

                    metrics
                        .vfs_merge_conflicts_total
                        .with_label_values(&["fast_path"])
                        .inc_by(report.stage0_fast_forwards as u64);
                    metrics
                        .vfs_merge_conflicts_total
                        .with_label_values(&["line_diff"])
                        .inc_by(report.stage1_line_merges as u64);
                    metrics
                        .vfs_merge_conflicts_total
                        .with_label_values(&["cst_ast"])
                        .inc_by(report.stage2_cst_merges as u64);
                    metrics
                        .vfs_merge_conflicts_total
                        .with_label_values(&["unresolved_conflict"])
                        .inc_by(report.stage3_conflicts as u64);
                }
            }
        }

        Ok(all_messages.into_iter().flatten().collect())
    }
}
pub struct ToolAccessClassifier;
impl ToolAccessClassifier {
    pub fn classify(tool_name: &str, input: &serde_json::Value) -> ToolAccessFootprint {
        base::tools_meta::classify_tool_footprint(tool_name, input)
    }
}
