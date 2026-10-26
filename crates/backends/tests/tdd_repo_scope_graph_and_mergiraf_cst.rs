use backends::merge::{VfsMergeConflict, merge_subagent_trees};
use base::ast::FileData;
use base::vfs_tree::VfsTree;
use chrono::Utc;
use std::sync::Arc;

#[test]
fn test_mergiraf_cst_merger() {
    let now = Utc::now();
    let mut base_tree = VfsTree::new();

    // Rust file
    let base_rs = "fn main() {\n    let a = 1;\n    let b = 2;\n    println!(\"{}\", a + b);\n}\n";
    let base_rs_data = Arc::new(FileData::new_utf8(base_rs.to_string(), now));
    base_tree
        .insert("/src/main.rs".to_string(), base_rs_data)
        .unwrap();

    let mut branch_a = VfsTree::new();
    let a_rs = "fn main() {\n    let a = 100;\n    let b = 2;\n    println!(\"{}\", a + b);\n}\n";
    let a_rs_data = Arc::new(FileData::new_utf8(a_rs.to_string(), now));
    branch_a
        .insert("/src/main.rs".to_string(), a_rs_data)
        .unwrap();

    let mut branch_b = VfsTree::new();
    let b_rs = "fn main() {\n    let a = 1;\n    let b = 200;\n    println!(\"{}\", a + b);\n}\n";
    let b_rs_data = Arc::new(FileData::new_utf8(b_rs.to_string(), now));
    branch_b
        .insert("/src/main.rs".to_string(), b_rs_data)
        .unwrap();

    let branches = vec![
        ("BranchA".to_string(), branch_a),
        ("BranchB".to_string(), branch_b),
    ];

    let report = merge_subagent_trees(&base_tree, branches, now);

    let merged_file = report.merged_tree.get("/src/main.rs").unwrap();
    let merged_str = std::str::from_utf8(&merged_file.content).unwrap();

    // The CST merge should handle this gracefully
    assert!(merged_str.contains("let a = 100;") || merged_str.contains("let a = 1;"));
    assert!(merged_str.contains("let b = 200;") || merged_str.contains("let b = 2;"));

    // Test write-write conflict (stage 3)
    let mut branch_c = VfsTree::new();
    let c_rs = "fn main() {\n    let a = 500;\n    let b = 2;\n    println!(\"{}\", a + b);\n}\n";
    let c_rs_data = Arc::new(FileData::new_utf8(c_rs.to_string(), now));
    branch_c
        .insert("/src/main.rs".to_string(), c_rs_data)
        .unwrap();

    let mut branch_d = VfsTree::new();
    let d_rs = "fn main() {\n    let a = 900;\n    let b = 2;\n    println!(\"{}\", a + b);\n}\n";
    let d_rs_data = Arc::new(FileData::new_utf8(d_rs.to_string(), now));
    branch_d
        .insert("/src/main.rs".to_string(), d_rs_data)
        .unwrap();

    let branches2 = vec![
        ("BranchC".to_string(), branch_c),
        ("BranchD".to_string(), branch_d),
    ];
    let report2 = merge_subagent_trees(&base_tree, branches2, now);

    assert!(report2.stage3_conflicts > 0);
    assert_eq!(report2.conflicts.len(), 1);

    if let VfsMergeConflict::WriteWriteConflict {
        path,
        branch_a,
        branch_b,
    } = &report2.conflicts[0]
    {
        assert_eq!(path, "/src/main.rs");
        assert_eq!(branch_a, "BranchC");
        assert_eq!(branch_b, "BranchD");
    } else {
        panic!("Expected WriteWriteConflict");
    }
}
