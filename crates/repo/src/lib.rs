#![allow(clippy::all)]
pub mod indexer;
pub mod linting_hooks;
pub mod parser;

/// A diagnostic message extracted from a Concrete Syntax Tree.
#[derive(Debug, Clone, PartialEq)]
pub struct CstDiagnostic {
    /// The 1-based start line of the diagnostic.
    pub start_line: usize,
    /// The 1-based start column of the diagnostic.
    pub start_col: usize,
    /// The 1-based end line of the diagnostic.
    pub end_line: usize,
    /// The 1-based end column of the diagnostic.
    pub end_col: usize,
    /// The source code snippet corresponding to the diagnostic.
    pub snippet: String,
    /// The diagnostic message.
    pub message: String,
}

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
pub mod scope_graph;
