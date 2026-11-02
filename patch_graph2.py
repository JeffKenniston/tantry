with open("crates/repo/src/graph.rs", "r") as f:
    code = f.read()

# Fix sigma_mut warnings
code = code.replace("let mut sigma_mut = 0.0;", "let sigma_mut;")
code = code.replace("let mut signature_mutated = false;", "let signature_mutated;")

with open("crates/repo/src/graph.rs", "w") as f:
    f.write(code)
