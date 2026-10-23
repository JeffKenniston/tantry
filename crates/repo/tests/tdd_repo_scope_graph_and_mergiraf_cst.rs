use base::vfs_tree::VfsTree;
use repo::indexer::Indexer;

#[test]
fn test_indexer() {
    let db_path = "file::memory:?cache=shared";
    let indexer = Indexer::new(db_path).unwrap();
    let vfs = VfsTree::new();
    let dirty = indexer.get_dirty_files(&vfs).unwrap();
    assert!(dirty.is_empty());
}
