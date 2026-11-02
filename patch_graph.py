with open("crates/repo/src/graph.rs", "r") as f:
    code = f.read()

import re

# Remove HybridSymbolMatch from impl block
code = code.replace("""    /// Represents a hybrid symbol match.
#[derive(Debug, Clone)]
    pub struct HybridSymbolMatch {
        pub symbol_id: String,
        pub rrf_score: f64,
    }""", "")

with open("crates/repo/src/graph.rs", "w") as f:
    f.write(code)
