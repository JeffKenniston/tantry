use crate::CstDiagnostic;
use tree_sitter::Tree;

pub fn check_cst_diagnostics(path: &str, tree: &Tree, source: &str) -> Vec<CstDiagnostic> {
    let mut diagnostics = Vec::new();
    let _cursor = tree.walk();
    let mut stack = vec![tree.root_node()];

    while let Some(node) = stack.pop() {
        if node.is_error() || node.is_missing() {
            let start = node.start_position();
            let end = node.end_position();
            let start_byte = node.start_byte();
            let end_byte = node.end_byte();
            let snippet = source[start_byte..end_byte].to_string();

            diagnostics.push(CstDiagnostic {
                start_line: start.row + 1,
                start_col: start.column + 1,
                end_line: end.row + 1,
                end_col: end.column + 1,
                snippet,
                message: format!("Syntax error at {path}:{}:{}", start.row + 1, start.column + 1),
            });
        }

        // Add children to stack
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }

    diagnostics
}
