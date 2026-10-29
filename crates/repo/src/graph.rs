use base::ast::BlastRadiusReport;
use base::path::PosixPath;
use std::collections::HashMap;

/// Represents a directed edge in the symbol call graph.
#[derive(Debug, Clone, PartialEq)]
pub struct SymbolEdge {
    /// The ID of the calling symbol.
    pub caller_id: String,
    /// The ID of the called symbol.
    pub callee_id: String,
    /// The kind of call (e.g., function call, trait method).
    pub call_kind: String,
    /// The file path where this call occurs.
    pub file_path: String,
}

/// Phase 2: Damped Katz Centrality Blast Radius calculator.
pub struct GraphCentrality {
    edges: Vec<SymbolEdge>,
}

impl GraphCentrality {
    /// Creates a new `GraphCentrality` structure.
    pub fn new() -> Self {
        Self { edges: Vec::new() }
    }

    /// Adds a directed edge to the graph.
    pub fn add_edge(
        &mut self,
        caller: String,
        callee: String,
        call_kind: String,
        file_path: String,
    ) {
        self.edges.push(SymbolEdge {
            caller_id: caller,
            callee_id: callee,
            call_kind,
            file_path,
        });
    }

    /// Computes Katz Centrality for nodes in the graph using an iterative approach.
    pub fn compute_katz_centrality_iterative(&self) -> HashMap<String, f32> {
        let mut centrality: HashMap<String, f32> = HashMap::new();
        let alpha = 0.15;
        let beta = 1.0;
        let mut nodes = std::collections::HashSet::new();

        let mut in_edges: HashMap<String, Vec<String>> = HashMap::new();
        for edge in &self.edges {
            nodes.insert(edge.caller_id.clone());
            nodes.insert(edge.callee_id.clone());
            in_edges
                .entry(edge.callee_id.clone())
                .or_default()
                .push(edge.caller_id.clone());
        }

        for node in &nodes {
            centrality.insert(node.clone(), beta);
        }

        for _ in 0..30 {
            let mut new_centrality = HashMap::new();
            let mut max_diff: f32 = 0.0;

            for node in &nodes {
                let mut sum = 0.0;
                if let Some(callers) = in_edges.get(node) {
                    for caller in callers {
                        sum += centrality.get(caller).unwrap_or(&0.0);
                    }
                }
                let new_val = beta + alpha * sum;
                let diff = (new_val - centrality.get(node).unwrap_or(&0.0)).abs();
                if diff > max_diff {
                    max_diff = diff;
                }
                new_centrality.insert(node.clone(), new_val);
            }
            centrality = new_centrality;
            if max_diff < 1e-5 {
                break;
            }
        }

        centrality
    }

    /// Transitive Reverse-Dependency Recursive CTE implementation.
    pub fn transitive_reverse_dependency_cte(&self, caller_id: &str) -> Vec<(String, String, u32)> {
        let mut result = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        let mut visited = std::collections::HashSet::new();

        queue.push_back((caller_id.to_string(), 0));
        visited.insert(caller_id.to_string());

        while let Some((current_node, depth)) = queue.pop_front() {
            if depth >= 16 {
                continue;
            }

            for edge in &self.edges {
                #[allow(clippy::collapsible_if)]
                if edge.callee_id == current_node {
                    if !visited.contains(&edge.caller_id) {
                        visited.insert(edge.caller_id.clone());
                        result.push((edge.caller_id.clone(), edge.file_path.clone(), depth + 1));
                        queue.push_back((edge.caller_id.clone(), depth + 1));
                    }
                }
            }
        }

        result
    }

    /// Hybrid Symbol Search using FTS5 and Vector Store logic via Reciprocal Rank Fusion.
    pub fn search_symbols_hybrid(
        &self,
        db_conn: &rusqlite::Connection,
        query_text: &str,
        query_embedding: &[f32],
        vector_store: &data::vector_index::MatryoshkaVectorStore,
        top_k: usize,
    ) -> Result<Vec<String>, String> {
        // 1. BM25 FTS5 Search
        let mut bm25_ranks = std::collections::HashMap::new();
        let mut stmt = db_conn
            .prepare(
                "SELECT symbol_id FROM symbols_fts WHERE symbols_fts MATCH ? ORDER BY rank LIMIT ?",
            )
            .map_err(|e| e.to_string())?;

        let mut rows = stmt
            .query(rusqlite::params![query_text, top_k as i64])
            .map_err(|e| e.to_string())?;
        let mut rank = 1;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let symbol_id: String = row.get(0).map_err(|e| e.to_string())?;
            bm25_ranks.insert(symbol_id, rank);
            rank += 1;
        }

        // 2. Vector Search using MatryoshkaVectorStore
        let vector_results = vector_store
            .search(query_embedding, top_k, 0.0)
            .map_err(|e| e.to_string())?;

        let mut vec_ranks = std::collections::HashMap::new();
        for (i, (symbol_id, _)) in vector_results.into_iter().enumerate() {
            vec_ranks.insert(symbol_id, i + 1);
        }

        // 3. Reciprocal Rank Fusion
        let mut rrf_scores: std::collections::HashMap<String, f64> =
            std::collections::HashMap::new();
        let k = 60.0;

        for (sym, rank) in bm25_ranks {
            let score = 1.0 / (k + rank as f64);
            *rrf_scores.entry(sym).or_insert(0.0) += score;
        }

        for (sym, rank) in vec_ranks {
            let score = 1.0 / (k + rank as f64);
            *rrf_scores.entry(sym).or_insert(0.0) += score;
        }

        let mut sorted: Vec<(String, f64)> = rrf_scores.into_iter().collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let res = sorted.into_iter().map(|(s, _)| s).take(top_k).collect();
        Ok(res)
    }

    /// Computes a risk score based on Katz centrality, affected files, and mutation type.
    pub fn compute_risk_score(
        &self,
        _target_symbol: &str,
        katz: f32,
        affected_files: usize,
        public_trait_impls: usize,
        signature_mutated: bool,
    ) -> f32 {
        let sigma_mut = if signature_mutated { 1.0 } else { 0.35 };
        let base_val =
            0.20 * katz + 0.40 * (affected_files as f32) + 0.50 * (public_trait_impls as f32);
        let exponent = -(sigma_mut * base_val) / 10.0;
        let risk = 1.0 - exponent.exp();
        risk.clamp(0.0, 1.0)
    }

    /// Constructs an AST Blast Radius report for a mutated symbol.
    pub fn ast_blast_radius(
        &self,
        target_symbol: &str,
        affected_files: Vec<PosixPath>,
        signature_mutated: bool,
        public_trait_impls: usize,
    ) -> BlastRadiusReport {
        let katz_map = self.compute_katz_centrality_iterative();
        let katz = *katz_map.get(target_symbol).unwrap_or(&1.0);

        let rev_deps = self.transitive_reverse_dependency_cte(target_symbol);
        let reverse_dependency_count = rev_deps.len();
        let max_depth_reached = rev_deps.iter().map(|(_, _, d)| *d).max().unwrap_or(0) as usize;

        let risk_score = self.compute_risk_score(
            target_symbol,
            katz,
            affected_files.len(),
            public_trait_impls,
            signature_mutated,
        );

        BlastRadiusReport {
            target_symbol: target_symbol.to_string(),
            affected_files,
            reverse_dependency_count,
            max_depth_reached,
            katz_centrality: katz,
            signature_mutated,
            risk_score,
        }
    }
}

impl Default for GraphCentrality {
    fn default() -> Self {
        Self::new()
    }
}
