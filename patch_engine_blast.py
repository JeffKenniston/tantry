import re

with open("crates/repo/src/engine.rs", "r") as f:
    code = f.read()

# Fix blast radius computation in engine.rs
old_blast = """        for def in scope_graph.definitions.values() {
            let br =
                centrality.ast_blast_radius(&def.symbol_id, vec![def.file_path.clone()], true, 0);
            if br.risk_score > max_risk_score {
                max_risk_score = br.risk_score;
            }
            blast_radius.push(br);
        }"""

new_blast = """        for symbol_def in scope_graph.definitions.values() {
            if let Ok(br) = centrality.compute_blast_radius(&conn, None, Some(symbol_def)) {
                if br.risk_score > max_risk_score {
                    max_risk_score = br.risk_score;
                }
                blast_radius.push(br);
            }
        }"""
code = code.replace(old_blast, new_blast)

with open("crates/repo/src/engine.rs", "w") as f:
    f.write(code)
