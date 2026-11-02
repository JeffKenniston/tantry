import re

with open("crates/repo/src/engine.rs", "r") as f:
    code = f.read()

# Modify fts creation logic
new_fts_sql = """CREATE VIRTUAL TABLE IF NOT EXISTS symbols_fts USING fts5(
                symbol_id UNINDEXED, name, qualified_name, signature_text, file_path
            );"""

code = code.replace("""CREATE VIRTUAL TABLE IF NOT EXISTS symbols_fts USING fts5(
                symbol_id, file_path, scope_qualified_name
            );""", new_fts_sql)


with open("crates/repo/src/engine.rs", "w") as f:
    f.write(code)
