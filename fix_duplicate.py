with open("crates/data/src/vector_index.rs", "r") as f:
    content = f.read()

import re
# Remove one of the duplicate from_handle functions
content = re.sub(r'pub fn from_handle\(db: Arc<parking_lot::Mutex<Connection>>\) -> Self \{\n        Self \{ db \}\n    \}\n', '', content, count=1)

with open("crates/data/src/vector_index.rs", "w") as f:
    f.write(content)
