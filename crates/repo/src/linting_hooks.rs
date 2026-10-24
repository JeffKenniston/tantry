use crate::CstDiagnostic;
use tree_sitter::Tree;

/// Synchronously extracts diagnostics from a parsed CST by walking the syntax tree.
/// Returns a list of `CstDiagnostic` where nodes are marked as errors or missing.
pub fn check_cst_diagnostics(path: &str, tree: &Tree, source: &str) -> Vec<CstDiagnostic> {
    let mut diagnostics = Vec::new();
    let mut cursor = tree.walk();

    let mut reached_root = false;
    while !reached_root {
        let node = cursor.node();

        if node.is_error() || node.is_missing() {
            let start = node.start_position();
            let end = node.end_position();
            let start_byte = node.start_byte();
            let end_byte = node.end_byte();

            // Defend against byte ranges out of bounds
            let snippet =
                if start_byte <= source.len() && end_byte <= source.len() && start_byte <= end_byte
                {
                    source[start_byte..end_byte].to_string()
                } else {
                    String::new()
                };

            diagnostics.push(CstDiagnostic {
                start_line: start.row + 1,
                start_col: start.column + 1,
                end_line: end.row + 1,
                end_col: end.column + 1,
                snippet,
                message: format!(
                    "Syntax error at {path}:{}:{}",
                    start.row + 1,
                    start.column + 1
                ),
            });
        }

        if cursor.goto_first_child() {
            continue;
        }

        if cursor.goto_next_sibling() {
            continue;
        }

        loop {
            if !cursor.goto_parent() {
                reached_root = true;
                break;
            }
            if cursor.goto_next_sibling() {
                break;
            }
        }
    }

    diagnostics
}
