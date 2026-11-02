with open("crates/repo/src/graph.rs", "r") as f:
    code = f.read()
code = code.replace("use base::path::PosixPath;", "")
with open("crates/repo/src/graph.rs", "w") as f:
    f.write(code)
