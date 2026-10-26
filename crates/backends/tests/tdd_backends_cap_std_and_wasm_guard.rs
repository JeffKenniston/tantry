use backends::local_fs::LocalFsBackend;
use backends::traits::VfsBackend;
use base::state::TantryState;
use base::vfs_tree::VfsTree;
use std::os::unix::fs::symlink;
use tempfile::tempdir;

fn create_mock_state() -> TantryState {
    TantryState {
        thread_id: "test".to_string(),
        step_index: 0,
        last_checkpoint_id: None,
        messages: vec![],
        files: VfsTree::new(),
        todos: vec![],
        skills_metadata: vec![],
        memory_contents: std::collections::BTreeMap::new(),
        async_tasks: std::collections::BTreeMap::new(),
        rubric_input: None,
        rubric_status: None,
        structured_response: None,
        extensions: base::typemap::StateExtensionMap::new(),
    }
}

#[test]
#[cfg(unix)]
fn test_local_fs_blocks_symlink_escape() {
    let dir = tempdir().unwrap();
    let root_path = dir.path();
    let backend = LocalFsBackend::new(root_path).unwrap();
    let state = create_mock_state();

    let symlink_path = root_path.join("escape");
    symlink("/etc/passwd", &symlink_path).unwrap();

    let result = backend.read_file(&state, "/escape", None, None);
    assert!(result.is_err());
}

#[test]
fn test_local_fs_ls_glob_grep() {
    let dir = tempdir().unwrap();
    let root_path = dir.path();
    std::fs::create_dir(root_path.join("foo")).unwrap();
    let backend = LocalFsBackend::new(root_path).unwrap();
    let mut state = create_mock_state();

    backend
        .write_file(&mut state, "/test.txt", "hello\nworld")
        .unwrap();
    backend
        .write_file(&mut state, "/foo/bar.txt", "match this\ntest")
        .unwrap();

    let ls_res = backend.ls(&state, "/").unwrap();
    assert_eq!(ls_res.len(), 2);

    let mut glob_res = backend.glob(&state, "**/*.txt").unwrap();
    glob_res.sort();
    assert_eq!(
        glob_res,
        vec!["/foo/bar.txt".to_string(), "/test.txt".to_string()]
    );

    let grep_res = backend.grep(&state, "match", None).unwrap();
    assert_eq!(grep_res.len(), 1);
    assert_eq!(grep_res[0].path, "/foo/bar.txt");
    assert_eq!(grep_res[0].content, "match this");
}

#[test]
fn test_wasm_guard_rejects_start_section() {
    use backends::error::BackendError;
    use backends::wasm::validate_component_no_start_yield;

    let safe_wasm: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    assert!(validate_component_no_start_yield(safe_wasm).is_ok());

    // Minimal WASM with start section
    let unsafe_wasm: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, // start section
    ];
    let err = validate_component_no_start_yield(unsafe_wasm).unwrap_err();
    assert!(matches!(err, BackendError::UnsafeWasmStartSection));
}

#[test]
fn test_termux_zygote_reap() {
    use backends::termux_supervisor::TermuxZygotePool;

    let pool = TermuxZygotePool::new(20);
    assert!(pool.max_workers <= 8);

    // Negative tests for reaping, should just pass without ESRCH
    assert!(TermuxZygotePool::reap_process_group(99999).is_ok());
}

#[test]
fn test_egress_proxy_blocks_unallowlisted() {
    use backends::egress_proxy::EgressProxy;
    use iam::tunnel_grant::ScopedTunnelRegistry;

    let registry = std::sync::Arc::new(ScopedTunnelRegistry::new());

    // We need to issue a grant to make it active, but WorkloadSvid isn't easily instantiable here because it requires crypto keys.
    // We'll mock the registry behavior.

    // The registry is used in EgressProxy. Let's just create a grant.

    let proxy = EgressProxy::new(vec!["crates.io".to_string()], registry);

    // Allowlisted
    assert!(proxy.evaluate_connection("crates.io", 0).is_ok());

    // Blocked
    assert!(proxy.evaluate_connection("malicious.com", 0).is_err());
}
