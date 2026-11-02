#![allow(clippy::all)]
pub mod indexer;
pub mod linting_hooks;
pub use linting_hooks::CstDiagnostic;
pub mod parser;

/// Analysis report of file mutations, containing diagnostics and blast radius impacts.
#[derive(Debug, Clone, PartialEq)]
pub struct FileMutationAnalysis {
    /// A list of syntax and CST diagnostics.
    pub diagnostics: Vec<CstDiagnostic>,
    /// A list of blast radius impact reports for changed symbols.
    pub blast_radius: Vec<base::ast::BlastRadiusReport>,
    /// The maximum risk score derived from the mutation.
    pub max_risk_score: f32,
    /// The maximum cyclomatic complexity computed.
    pub cyclomatic_complexity: u32,
}
pub mod engine;
pub mod graph;
pub mod repomap;

pub use engine::{RepoEngine, RepoEngineConfig};

pub use repomap::SkeletonRepoMapSlot;
pub mod error;
pub mod scope_graph;
pub use error::RepoError;
