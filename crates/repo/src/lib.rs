pub mod indexer;
pub mod linting_hooks;
pub mod parser;

#[derive(Debug, Clone, PartialEq)]
pub struct CstDiagnostic {
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
    pub snippet: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileMutationAnalysis {
    pub diagnostics: Vec<CstDiagnostic>,
    pub blast_radius: Vec<base::ast::BlastRadiusReport>,
    pub max_risk_score: f32,
    pub cyclomatic_complexity: u32,
}
