use std::collections::{BTreeMap, BTreeSet};

use base::ast::ContentBlock;
use base::path::PosixPath;
use base::tools_meta::ToolAccessFootprint;

/// Represents a scheduled wave of tool calls.
#[derive(Debug, Clone)]
pub struct ToolWave {
    pub wave_index: usize,
    pub tool_calls: Vec<ContentBlock>,
}

/// A DAG representation of tool call dependencies.
#[derive(Debug, Default)]
pub struct BernsteinConflictDag {
    pub nodes: BTreeMap<usize, ContentBlock>,
    pub edges: BTreeMap<usize, BTreeSet<usize>>, // i -> j means j depends on i
    pub in_degrees: BTreeMap<usize, usize>,
}

impl BernsteinConflictDag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, index: usize, block: ContentBlock) {
        self.nodes.insert(index, block);
        self.in_degrees.entry(index).or_insert(0);
        self.edges.entry(index).or_insert_with(BTreeSet::new);
    }

    pub fn add_edge(&mut self, from: usize, to: usize) {
        if self.edges.get_mut(&from).unwrap().insert(to) {
            *self.in_degrees.entry(to).or_insert(0) += 1;
        }
    }
}

pub struct BernsteinToolScheduler;

impl BernsteinToolScheduler {
    /// Extracts the footprint for a tool call.
    fn extract_footprint(block: &ContentBlock) -> Option<ToolAccessFootprint> {
        if let ContentBlock::ToolUse { name, input, .. } = block {
            let path_arg = input.get("path").and_then(|v| v.as_str()).map(|s| s.to_string());
            Some(ToolAccessFootprint::for_tool(name, path_arg))
        } else {
            None
        }
    }

    /// Checks intersection of two paths.
    fn paths_intersect(p1: &str, p2: &str) -> bool {
        if p1 == "/**" || p2 == "/**" {
            return true;
        }
        if p1 == p2 {
            return true;
        }
        let p1_parts: Vec<&str> = p1.split('/').filter(|s| !s.is_empty()).collect();
        let p2_parts: Vec<&str> = p2.split('/').filter(|s| !s.is_empty()).collect();

        let min_len = std::cmp::min(p1_parts.len(), p2_parts.len());
        for i in 0..min_len {
            if p1_parts[i] != p2_parts[i] {
                return false;
            }
        }
        true
    }

    /// Checks if two sets of paths intersect.
    fn path_sets_intersect(s1: &[PosixPath], s2: &[PosixPath]) -> bool {
        for p1 in s1 {
            for p2 in s2 {
                if Self::paths_intersect(p1, p2) {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if two footprints conflict according to Bernstein's condition.
    pub fn is_conflict(f1: &ToolAccessFootprint, f2: &ToolAccessFootprint) -> bool {
        if f1.is_global_barrier || f2.is_global_barrier {
            return true;
        }

        let w1_w2 = Self::path_sets_intersect(&f1.writes, &f2.writes);
        let r1_w2 = Self::path_sets_intersect(&f1.reads, &f2.writes);
        let w1_r2 = Self::path_sets_intersect(&f1.writes, &f2.reads);

        w1_w2 || r1_w2 || w1_r2
    }

    /// Partitions tool calls into waves using Kahn's algorithm.
    pub fn partition_waves(tool_calls: Vec<ContentBlock>) -> Vec<ToolWave> {
        let mut dag = BernsteinConflictDag::new();
        let mut footprints = Vec::new();

        for (i, block) in tool_calls.iter().enumerate() {
            dag.add_node(i, block.clone());
            footprints.push(Self::extract_footprint(block).unwrap_or_else(|| {
                ToolAccessFootprint {
                    reads: vec!["/**".to_string()],
                    writes: vec!["/**".to_string()],
                    is_global_barrier: true,
                    is_mutating_for_semantic_cache: true,
                }
            }));
        }

        let n = tool_calls.len();
        for i in 0..n {
            for j in (i + 1)..n {
                if Self::is_conflict(&footprints[i], &footprints[j]) {
                    dag.add_edge(i, j);
                }
            }
        }

        let mut waves = Vec::new();
        let mut wave_index = 0;

        let mut in_degrees = dag.in_degrees.clone();

        loop {
            let mut current_wave_nodes = Vec::new();
            for (&node, &degree) in &in_degrees {
                if degree == 0 {
                    current_wave_nodes.push(node);
                }
            }

            if current_wave_nodes.is_empty() {
                break;
            }

            let mut wave_blocks = Vec::new();
            for &node in &current_wave_nodes {
                in_degrees.remove(&node);
                wave_blocks.push(dag.nodes.get(&node).unwrap().clone());

                if let Some(neighbors) = dag.edges.get(&node) {
                    for &neighbor in neighbors {
                        if let Some(deg) = in_degrees.get_mut(&neighbor) {
                            *deg -= 1;
                        }
                    }
                }
            }

            waves.push(ToolWave {
                wave_index,
                tool_calls: wave_blocks,
            });
            wave_index += 1;
        }

        waves
    }
}
