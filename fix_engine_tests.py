with open("crates/runtime/tests/engine_tests.rs", "r") as f:
    content = f.read()
import re
content = re.sub(r'DataStoreManager::new\(&db_l, &db_i, &db_a, &db_v\)', 'DataStoreManager::open(&root, data::AeadCipherSuite::XChaCha20Poly1305, &base::platform::RuntimePlatform::LinuxStandard)', content)
content = re.sub(r'let db_[liav] = format!\("\{}/[liav]", root\);\n\s*', '', content)
content = re.sub(r'FsCapability::Base\(Arc::new\(\s*permissions::glob_dfa::CompiledFsAutomaton::new\(fs_mode,\s*vec!\[\]\)\.unwrap\(\),\s*\)\)', 'FsCapability::new(vec![], fs_mode).unwrap()', content)
content = re.sub(r'EnvCapability::new\(vec!\[\],\s*vec!\[\]\)', 'EnvCapability::compile(vec![], std::collections::BTreeSet::new(), permissions::lattice::PermissionMode::Allow)', content)
content = re.sub(r'McpCapability::new\(PermissionMode::Allow,\s*1000000,\s*1000000,\s*vec!\[\]\)', 'McpCapability::new(PermissionMode::Allow, 1000000, vec![])', content)
with open("crates/runtime/tests/engine_tests.rs", "w") as f:
    f.write(content)
