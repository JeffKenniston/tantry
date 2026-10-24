use backends::traits::VfsBackend;
use backends::local_fs::LocalFsBackend;
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

    backend.write_file(&mut state, "/test.txt", "hello\nworld").unwrap();
    backend.write_file(&mut state, "/foo/bar.txt", "match this\ntest").unwrap();

    let ls_res = backend.ls(&state, "/").unwrap();
    assert_eq!(ls_res.len(), 2);

    let mut glob_res = backend.glob(&state, "**/*.txt").unwrap();
    glob_res.sort();
    assert_eq!(glob_res, vec!["/foo/bar.txt".to_string(), "/test.txt".to_string()]);

    let grep_res = backend.grep(&state, "match", None).unwrap();
    assert_eq!(grep_res.len(), 1);
    assert_eq!(grep_res[0].path, "/foo/bar.txt");
    assert_eq!(grep_res[0].content, "match this");
}
