use base::ast::ToolCallId;
use base::path::PosixPath;
use base::tools_meta::ToolAccessFootprint;
use std::collections::BTreeMap;

/// Represents a node in the Bernstein conflict graph for tool execution.
#[derive(Debug)]
pub struct ToolNode {
    /// Internal index of the tool in the current turn.
    pub id: usize,
    /// Tool call ID.
    pub tool_use_id: ToolCallId,
    /// Memory footprint for Bernstein dependency checks.
    pub footprint: ToolAccessFootprint,
}

/// A Bernstein conflict DAG scheduler that orchestrates parallel execution of tool waves.
#[derive(Debug)]
pub struct BernsteinToolScheduler {
    /// List of tool nodes to schedule.
    pub nodes: Vec<ToolNode>,
    /// Adjacency list mapping node index to its dependents.
    pub adjacency: BTreeMap<usize, Vec<usize>>,
    /// In-degree (number of dependencies) for each node.
    pub in_degrees: BTreeMap<usize, usize>,
}

impl BernsteinToolScheduler {
    /// Creates a new scheduler and builds the dependency graph based on Bernstein's condition.
    pub fn new(nodes: Vec<ToolNode>) -> Self {
        let mut adjacency: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut in_degrees: BTreeMap<usize, usize> = BTreeMap::new();

        for i in 0..nodes.len() {
            in_degrees.insert(i, 0);
            adjacency.insert(i, Vec::new());
        }

        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                if Self::conflicts(&nodes[i].footprint, &nodes[j].footprint) {
                    adjacency.entry(i).or_default().push(j);
                    *in_degrees.entry(j).or_insert(0) += 1;
                }
            }
        }

        Self {
            nodes,
            adjacency,
            in_degrees,
        }
    }

    /// Evaluates if two footprints conflict according to Bernstein's condition.
    fn conflicts(a: &ToolAccessFootprint, b: &ToolAccessFootprint) -> bool {
        if a.is_global_barrier || b.is_global_barrier {
            return true;
        }

        Self::intersects(&a.writes, &b.writes)
            || Self::intersects(&a.reads, &b.writes)
            || Self::intersects(&a.writes, &b.reads)
    }

    /// Checks if two sets of paths intersect, handling exact matches and prefix containment.
    fn intersects(paths_a: &[PosixPath], paths_b: &[PosixPath]) -> bool {
        for a in paths_a {
            for b in paths_b {
                if a == b || a == "/**" || b == "/**" || a.starts_with(&format!("{}/", b)) || b.starts_with(&format!("{}/", a)) {
                    return true;
                }
            }
        }
        false
    }

    /// Topologically sorts the tools into waves (sets of mutually independent tools).
    pub fn schedule_waves(&self) -> Vec<Vec<usize>> {
        let mut in_degrees = self.in_degrees.clone();
        let mut waves = Vec::new();

        loop {
            let mut current_wave = Vec::new();
            for (&node, &degree) in &in_degrees {
                if degree == 0 {
                    current_wave.push(node);
                }
            }

            if current_wave.is_empty() {
                break;
            }

            for &node in &current_wave {
                in_degrees.remove(&node);
                if let Some(neighbors) = self.adjacency.get(&node) {
                    for neighbor in neighbors {
                        if let Some(deg) = in_degrees.get_mut(neighbor) {
                            *deg -= 1;
                        }
                    }
                }
            }

            current_wave.sort();
            waves.push(current_wave);
        }

        waves
    }
}
