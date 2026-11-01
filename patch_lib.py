with open("crates/data/src/lib.rs", "r") as f:
    content = f.read()
import re
content = re.sub(r'use crate::error::DataError;\nuse iam::IdentityManager;\nuse std::sync::Arc;\n', '', content)
content = re.sub(r'/// The boolean result of a full cryptographic consistency verification[\s\S]*$', 'pub use db::DataStoreManager;\n', content)
with open("crates/data/src/lib.rs", "w") as f:
    f.write(content)
