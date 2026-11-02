use tree_sitter::Tree;

/// A diagnostic message extracted from a Concrete Syntax Tree.
#[derive(Debug, Clone, PartialEq)]
pub struct CstDiagnostic {
    pub file_path: String,
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
    pub is_missing: bool,
    pub snippet: String,
    pub message: String,
}

/// Phase 1: Synchronously extracts diagnostics from a parsed CST by walking the syntax tree.
/// Returns a list of `CstDiagnostic` where nodes are marked as errors or missing.
pub fn check_cst_diagnostics(path: &str, tree: &Tree, source: &str) -> Vec<CstDiagnostic> {
    if !tree.root_node().has_error() {
        return Vec::new();
    }

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
                    let full_line = source.lines().nth(start.row).unwrap_or("").trim();
                    full_line.chars().take(120).collect()
                } else {
                    String::new()
                };

            let message = format!(
                "{}:{}:{}: syntax {} near `{}`",
                path,
                start.row + 1,
                start.column + 1,
                if node.is_missing() {
                    "missing token"
                } else {
                    "error"
                },
                snippet
            );

            diagnostics.push(CstDiagnostic {
                file_path: path.to_string(),
                start_line: start.row + 1,
                start_col: start.column + 1,
                end_line: end.row + 1,
                end_col: end.column + 1,
                is_missing: node.is_missing(),
                snippet,
                message,
            });

            if node.is_error() {
                // Skip descending into children of an already-reported ERROR node
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
                continue;
            }
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

pub fn format_diagnostics_for_tool_output(diagnostics: &[CstDiagnostic]) -> Option<String> {
    if diagnostics.is_empty() {
        None
    } else {
        let mut out = String::from("\n[CST Syntax Diagnostics]\n");
        for diag in diagnostics {
            out.push_str(&format!("{}\n", diag.message));
        }
        Some(out)
    }
}
