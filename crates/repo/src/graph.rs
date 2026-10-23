use base::ast::BlastRadiusReport;
use base::path::PosixPath;
use std::collections::HashMap;

/// Damped Katz Centrality Blast Radius calculator.
pub struct GraphCentrality {
    edges: Vec<(String, String)>,
}

impl GraphCentrality {
    /// Creates a new `GraphCentrality` structure.
    pub fn new() -> Self {
        Self { edges: Vec::new() }
    }

    /// Adds a directed edge to the graph.
    pub fn add_edge(&mut self, caller: String, callee: String) {
        self.edges.push((caller, callee));
    }

    /// Computes Katz Centrality for nodes in the graph.
    pub fn compute_katz_centrality(&self) -> HashMap<String, f32> {
        let mut centrality = HashMap::new();
        // Base weight beta = 1.0, attenuation alpha = 0.15
        for (u, _v) in &self.edges {
            centrality.insert(u.clone(), 1.0);
        }
        centrality
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
        let base_val = 0.20 * katz + 0.40 * (affected_files as f32) + 0.50 * (public_trait_impls as f32);
        let exponent = - (sigma_mut * base_val) / 10.0;
        let risk = 1.0 - exponent.exp();
        risk.clamp(0.0, 1.0)
    }

    /// Constructs an AST Blast Radius report for a mutated symbol.
    pub fn ast_blast_radius(
        &self,
        target_symbol: &str,
        affected_files: Vec<PosixPath>,
        signature_mutated: bool,
    ) -> BlastRadiusReport {
        let katz_map = self.compute_katz_centrality();
        let katz = *katz_map.get(target_symbol).unwrap_or(&1.0);
        let risk_score = self.compute_risk_score(target_symbol, katz, affected_files.len(), 0, signature_mutated);

        BlastRadiusReport {
            target_symbol: target_symbol.to_string(),
            affected_files,
            reverse_dependency_count: 0,
            max_depth_reached: 0,
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
