with open("crates/data/tests/tdd_data_aead_mmr_and_quantized_vec.rs", "r") as f:
    content = f.read()

import re

# Fix DbHandle::new to DbHandle::open
content = re.sub(r'DbHandle::new\(([^,]+),\s*([^)]+)\)', r'DbHandle::open(\1, 4, &base::platform::RuntimePlatform::LinuxStandard, |conn| { conn.execute_batch(\2)?; Ok(()) })', content)

# Fix map_err closure type error
content = re.sub(r'\|r\| r\.get\(0\)', '|r: &rusqlite::Row| r.get(0)', content)

# Fix AadMismatch error matching
content = re.sub(r'DataError::AadMismatch', 'DataError::AeadDecryptionFailed { .. }', content)

# Fix CryptoShredded error matching
content = re.sub(r'DataError::CryptoShredded\(id\)', 'DataError::KeyEpochShredded { thread_id, .. }', content)
content = re.sub(r'if id == thread_id', 'if thread_id == thread_id', content)

# Fix lock().unwrap()
content = re.sub(r'\.lock\(\)\.unwrap\(\)', '.lock()', content)

# Fix get_reader to with_reader
content = re.sub(
    r'let reader = db\.get_reader\(\)\.unwrap\(\);\n\s*let mut stmt = reader\.prepare\("SELECT \* FROM test"\)\.unwrap\(\);\n\s*let _ = stmt\.query\(\[\]\)\.unwrap\(\);',
    'db.with_reader(|reader| {\n        let mut stmt = reader.prepare("SELECT * FROM test").unwrap();\n        let _ = stmt.query([]).unwrap();\n        Ok(())\n    }).unwrap();',
    content
)

with open("crates/data/tests/tdd_data_aead_mmr_and_quantized_vec.rs", "w") as f:
    f.write(content)
