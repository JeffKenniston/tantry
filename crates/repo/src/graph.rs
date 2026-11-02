use base::ast::BlastRadiusReport;

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

#[derive(Debug, Clone)]
pub struct HybridSymbolMatch {
    pub symbol_id: String,
    pub rrf_score: f64,
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
    pub fn transitive_reverse_dependency_cte(
        &self,
        db_conn: &rusqlite::Connection,
        caller_id: &str,
    ) -> Result<Vec<(String, String, u32)>, crate::RepoError> {
        let mut stmt = db_conn.prepare(
            "WITH RECURSIVE transitive_callers(caller_id, caller_file, depth) AS (
                SELECT caller_id, file_path, 1
                FROM symbol_edges
                WHERE callee_id = ?1 AND caller_id != callee_id
              UNION ALL
                SELECT e.caller_id, e.file_path, tc.depth + 1
                FROM symbol_edges e
                JOIN transitive_callers tc ON e.callee_id = tc.caller_id
                WHERE tc.depth < 16 AND e.caller_id != e.callee_id
            )
            SELECT caller_id, caller_file, MIN(depth) as min_depth
            FROM transitive_callers
            GROUP BY caller_id, caller_file;",
        )?;

        let mut rows = stmt.query(rusqlite::params![caller_id])?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let caller: String = row.get(0)?;
            let file: String = row.get(1)?;
            let depth: u32 = row.get(2)?;
            result.push((caller, file, depth));
        }

        Ok(result)
    }

    /// Hybrid Symbol Search using FTS5 and Vector Store logic via Reciprocal Rank Fusion.
    pub fn search_symbols_hybrid(
        &self,
        db_conn: &rusqlite::Connection,
        query: &str,
        query_embedding: Option<&[f32]>,
        vector_store: Option<&data::vector_index::MatryoshkaVectorStore>,
        top_k: usize,
    ) -> Result<Vec<HybridSymbolMatch>, crate::RepoError> {
        // 1. BM25 FTS5 Search
        let mut bm25_ranks = std::collections::HashMap::new();
        let mut stmt = db_conn
            .prepare(
                "SELECT symbol_id FROM symbols_fts WHERE symbols_fts MATCH ? ORDER BY bm25(symbols_fts)",
            )?;

        let mut rows = stmt.query(rusqlite::params![query])?;
        let mut rank = 1;
        while let Some(row) = rows.next()? {
            let symbol_id: String = row.get(0)?;
            bm25_ranks.insert(symbol_id, rank);
            rank += 1;
        }

        // 2. Vector Search using MatryoshkaVectorStore
        let mut vec_ranks = std::collections::HashMap::new();
        if let (Some(emb), Some(vs)) = (query_embedding, vector_store) {
            let vector_results = vs
                .search_top_k(emb, top_k * 2, 0.0)
                .map_err(|e| crate::RepoError::Analysis(e.to_string()))?;

            for (i, (symbol_id, _)) in vector_results.into_iter().enumerate() {
                vec_ranks.insert(symbol_id, i + 1);
            }
        }

        // 3. Reciprocal Rank Fusion
        let mut rrf_scores: std::collections::HashMap<String, f64> =
            std::collections::HashMap::new();

        for (sym, rank) in bm25_ranks {
            let score = 1.0 / (60.0 + rank as f64);
            *rrf_scores.entry(sym).or_insert(0.0) += score;
        }

        for (sym, rank) in vec_ranks {
            let score = 1.0 / (60.0 + rank as f64);
            *rrf_scores.entry(sym).or_insert(0.0) += score;
        }

        let mut sorted: Vec<(String, f64)> = rrf_scores.into_iter().collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let res = sorted
            .into_iter()
            .map(|(s, r)| HybridSymbolMatch {
                symbol_id: s,
                rrf_score: r,
            })
            .take(top_k)
            .collect();
        Ok(res)
    }

    /// Computes AST Blast Radius for a mutated symbol.
    pub fn compute_blast_radius(
        &self,
        db_conn: &rusqlite::Connection,
        old_def: Option<&crate::scope_graph::SymbolDef>,
        new_def: Option<&crate::scope_graph::SymbolDef>,
    ) -> Result<base::ast::BlastRadiusReport, crate::RepoError> {
        let sigma_mut;
        let signature_mutated;

        let target_symbol = match (old_def, new_def) {
            (Some(o), Some(n)) => {
                if o.signature_blake3 != n.signature_blake3 {
                    sigma_mut = 1.0;
                    signature_mutated = true;
                } else if o.body_blake3 != n.body_blake3 {
                    sigma_mut = 0.35;
                    signature_mutated = false;
                } else {
                    sigma_mut = 0.0;
                    signature_mutated = false;
                }
                &n.symbol_id
            }
            (Some(o), None) => {
                sigma_mut = 1.0;
                signature_mutated = true;
                &o.symbol_id
            }
            (None, Some(n)) => {
                sigma_mut = 0.35;
                signature_mutated = false;
                &n.symbol_id
            }
            (None, None) => {
                return Err(crate::RepoError::Analysis(
                    "Both old and new defs are None".to_string(),
                ));
            }
        };

        let katz_map = self.compute_katz_centrality_iterative();
        let katz = *katz_map.get(target_symbol).unwrap_or(&1.0);

        let rev_deps = self.transitive_reverse_dependency_cte(db_conn, target_symbol)?;
        let reverse_dependency_count = rev_deps.len();
        let max_depth_reached = rev_deps.iter().map(|(_, _, d)| *d).max().unwrap_or(0) as usize;

        let mut affected_files = std::collections::HashSet::new();
        if let Some(o) = old_def {
            affected_files.insert(o.file_path.clone());
        }
        if let Some(n) = new_def {
            affected_files.insert(n.file_path.clone());
        }

        // Count public trait impls. Here we use 0 since it is not fully extracted.
        // If we want to use exact logic, we extract from new_def.
        let public_trait_impls_count = if let Some(n) = new_def {
            if n.is_public_trait_impl { 1 } else { 0 }
        } else {
            0
        };

        let raw_exposure = 0.20 * (katz as f64)
            + 0.40 * (affected_files.len() as f64)
            + 0.50 * (public_trait_impls_count as f64);
        let risk_score = if sigma_mut == 0.0 {
            0.0
        } else {
            (1.0 - (-(sigma_mut * raw_exposure) / 10.0).exp()).clamp(0.0, 1.0) as f32
        };

        let affected_files_posix = affected_files
            .into_iter()
            .map(base::path::PosixPath::from)
            .collect();

        Ok(BlastRadiusReport {
            target_symbol: target_symbol.to_string(),
            affected_files: affected_files_posix,
            reverse_dependency_count,
            max_depth_reached,
            katz_centrality: katz,
            signature_mutated,
            risk_score,
        })
    }
}

impl Default for GraphCentrality {
    fn default() -> Self {
        Self::new()
    }
}
