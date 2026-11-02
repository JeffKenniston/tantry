import re

with open("crates/repo/tests/tdd_repo_scope_graph_and_mergiraf_cst.rs", "r") as f:
    code = f.read()

# Replace ast_blast_radius in tests with compute_blast_radius using memory connection
old_test_risk_score = """#[test]
fn test_risk_score_variance() {
    let centrality = GraphCentrality::new();
    let report_sig_mut =
        centrality.ast_blast_radius("sym1", vec!["/src/main.rs".to_string()], true, 0);
    let report_body_only =
        centrality.ast_blast_radius("sym1", vec!["/src/main.rs".to_string()], false, 0);

    assert!(report_sig_mut.risk_score > report_body_only.risk_score);
}"""

new_test_risk_score = """#[test]
fn test_risk_score_variance() {
    let centrality = GraphCentrality::new();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS symbol_edges (
            caller_id TEXT,
            callee_id TEXT,
            call_kind TEXT,
            file_path TEXT
        );"
    ).unwrap();

    let old_def = SymbolDef {
        symbol_id: "sym1".to_string(),
        kind: ScopeKind::Function,
        signature_blake3: [0u8; 32],
        body_blake3: [0u8; 32],
        file_path: "/src/main.rs".to_string(),
        scope_qualified_name: "sym1".to_string(),
        is_public_trait_impl: false,
    };

    let new_def_sig_mut = SymbolDef {
        symbol_id: "sym1".to_string(),
        kind: ScopeKind::Function,
        signature_blake3: [1u8; 32], // different signature
        body_blake3: [0u8; 32],
        file_path: "/src/main.rs".to_string(),
        scope_qualified_name: "sym1".to_string(),
        is_public_trait_impl: false,
    };

    let new_def_body_mut = SymbolDef {
        symbol_id: "sym1".to_string(),
        kind: ScopeKind::Function,
        signature_blake3: [0u8; 32], // same signature
        body_blake3: [1u8; 32], // different body
        file_path: "/src/main.rs".to_string(),
        scope_qualified_name: "sym1".to_string(),
        is_public_trait_impl: false,
    };

    let report_sig_mut = centrality.compute_blast_radius(&conn, Some(&old_def), Some(&new_def_sig_mut)).unwrap();
    let report_body_only = centrality.compute_blast_radius(&conn, Some(&old_def), Some(&new_def_body_mut)).unwrap();

    assert!(report_sig_mut.risk_score > report_body_only.risk_score);
}"""

code = code.replace(old_test_risk_score, new_test_risk_score)

with open("crates/repo/tests/tdd_repo_scope_graph_and_mergiraf_cst.rs", "w") as f:
    f.write(code)
