use base::delta::FileDelta;
use base::vfs_tree::VfsTree;
use base::ast::FileData;
use std::collections::HashMap;
use std::sync::Arc;
use tree_sitter::Parser;

/// Branch Operation for Three-Way Merge
pub enum BranchOp {
    /// Modify operation
    Modify(Arc<FileData>),
    /// Delete operation
    Delete,
}

/// A merge conflict struct
#[derive(Debug, PartialEq)]
pub enum VfsMergeConflict {
    /// Write/Write conflict
    WriteWriteConflict {
        /// path
        path: String,
        /// Branch A
        branch_a: String,
        /// Branch B
        branch_b: String,
    },
    /// Modify/Delete conflict
    ModifyDeleteConflict {
        /// path
        path: String,
        /// Branch that modified
        modified_by: String,
        /// Branch that deleted
        deleted_by: String,
    },
}

/// The result of a 3-way VFS Merge
#[derive(Default)]
pub struct VfsMergeReport {
    /// Conflicts
    pub conflicts: Vec<VfsMergeConflict>,
    /// Stage 0
    pub stage0_fast_forwards: u32,
    /// Stage 1
    pub stage1_line_merges: u32,
    /// Stage 2
    pub stage2_cst_merges: u32,
    /// Stage 3
    pub stage3_conflicts: u32,
    /// Merged Tree
    pub merged_tree: VfsTree,
}

/// 3-Way Merge algorithm across N branches
#[allow(clippy::collapsible_if)]
pub fn multi_way_merge(
    base: &VfsTree,
    branches: HashMap<String, VfsTree>,
    now: chrono::DateTime<chrono::Utc>,
) -> VfsMergeReport {
    let mut report = VfsMergeReport {
        merged_tree: base.clone(),
        ..Default::default()
    };

    let mut path_ops: HashMap<String, Vec<(String, BranchOp)>> = HashMap::new();

    // Stage 0: Merkle Fast-Forward & Delete/Modify Detection
    for (branch_name, branch_tree) in &branches {
        let deltas = base.diff(branch_tree);
        for delta in deltas {
            match delta {
                FileDelta::Upsert { path, data } => {
                    path_ops
                        .entry(path)
                        .or_default()
                        .push((branch_name.clone(), BranchOp::Modify(data)));
                }
                FileDelta::Delete { path } => {
                    path_ops
                        .entry(path)
                        .or_default()
                        .push((branch_name.clone(), BranchOp::Delete));
                }
            }
        }
    }

    for (path, ops) in path_ops {
        if ops.len() == 1 {
            let (_, op) = &ops[0];
            match op {
                BranchOp::Modify(data) => {
                    let _ = report.merged_tree.insert(path.clone(), data.clone());
                }
                BranchOp::Delete => {
                    let _ = report.merged_tree.remove(&path);
                }
            }
            report.stage0_fast_forwards += 1;
            continue;
        }

        let mut all_same_modify = true;
        let mut first_hash = None;
        let mut first_data = None;
        let mut has_delete = false;
        let mut modified_by = String::new();
        let mut deleted_by = String::new();

        for (branch_name, op) in &ops {
            match op {
                BranchOp::Modify(data) => {
                    if first_hash.is_none() {
                        first_hash = Some(data.blake3_hash);
                        first_data = Some(data.clone());
                        modified_by = branch_name.clone();
                    } else if first_hash != Some(data.blake3_hash) {
                        all_same_modify = false;
                    }
                }
                BranchOp::Delete => {
                    has_delete = true;
                    deleted_by = branch_name.clone();
                    all_same_modify = false;
                }
            }
        }

        if all_same_modify && !has_delete {
            if let Some(data) = first_data {
                let _ = report.merged_tree.insert(path.clone(), data);
                report.stage0_fast_forwards += 1;
            }
            continue;
        }

        if has_delete && first_hash.is_some() {
            report
                .conflicts
                .push(VfsMergeConflict::ModifyDeleteConflict {
                    path: path.clone(),
                    modified_by,
                    deleted_by,
                });
            continue;
        }

        if ops.len() == 2 {
            let (b1, op1) = &ops[0];
            let (b2, op2) = &ops[1];

            #[allow(clippy::collapsible_if)]
            if let (BranchOp::Modify(d1), BranchOp::Modify(d2)) = (op1, op2) {
                #[allow(clippy::collapsible_if)]
                if d1.is_utf8 && d2.is_utf8 {
                    #[allow(clippy::collapsible_if)]
                    if let Some(base_data) = base.get(&path) {
                        if base_data.is_utf8 {
                            let str_base = std::str::from_utf8(&base_data.content).unwrap_or("");
                            let str1 = std::str::from_utf8(&d1.content).unwrap_or("");
                            let str2 = std::str::from_utf8(&d2.content).unwrap_or("");

                            if let Some(merged_str) = three_way_merge(str_base, str1, str2) {
                                let new_data = FileData::new_utf8(merged_str, now);
                                let _ = report.merged_tree.insert(path.clone(), Arc::new(new_data));
                                report.stage1_line_merges += 1;
                                continue;
                            }

                            if let Some(cst_merged) = cst_merge(str_base, str1, str2, &path) {
                                let new_data = FileData::new_utf8(cst_merged, now);
                                let _ = report.merged_tree.insert(path.clone(), Arc::new(new_data));
                                report.stage2_cst_merges += 1;
                                continue;
                            }

                            let conflict_content = format!(
                                "<<<<<<< {}\n{}\n=======\n{}\n>>>>>>> {}\n",
                                b1, str1, str2, b2
                            );
                            let new_data = FileData::new_utf8(conflict_content, now);
                            let _ = report.merged_tree.insert(path.clone(), Arc::new(new_data));
                            report.stage3_conflicts += 1;
                            report.conflicts.push(VfsMergeConflict::WriteWriteConflict {
                                path: path.clone(),
                                branch_a: b1.clone(),
                                branch_b: b2.clone(),
                            });
                            continue;
                        }
                    }
                }
            }
        }

        let (b1, b2) = if ops.len() >= 2 {
            (ops[0].0.clone(), ops[1].0.clone())
        } else {
            ("unknown".to_string(), "unknown".to_string())
        };

        report.stage3_conflicts += 1;
        report.conflicts.push(VfsMergeConflict::WriteWriteConflict {
            path: path.clone(),
            branch_a: b1,
            branch_b: b2,
        });
    }

    report
}

/// Computes differences between two files by lines.
fn three_way_merge(base: &str, a: &str, b: &str) -> Option<String> {
    if a == b {
        return Some(a.to_string());
    }
    if a == base {
        return Some(b.to_string());
    }
    if b == base {
        return Some(a.to_string());
    }

    let a_lines: Vec<&str> = a.split('\n').collect();
    let b_lines: Vec<&str> = b.split('\n').collect();
    let base_lines: Vec<&str> = base.split('\n').collect();

    let mut merged = Vec::new();
    let mut i = 0;
    let mut j = 0;
    let mut k = 0;

    while i < base_lines.len() || j < a_lines.len() || k < b_lines.len() {
        let bl = base_lines.get(i);
        let al = a_lines.get(j);
        let bl2 = b_lines.get(k);

        if al == bl2 {
            if let Some(v) = al {
                merged.push(*v);
            }
            i += 1;
            j += 1;
            k += 1;
        } else if al == bl {
            if let Some(v) = bl2 {
                merged.push(*v);
            }
            i += 1;
            j += 1;
            k += 1;
        } else if bl2 == bl {
            if let Some(v) = al {
                merged.push(*v);
            }
            i += 1;
            j += 1;
            k += 1;
        } else {
            if i >= base_lines.len() {
                if let Some(a) = al {
                    if bl2.is_none() {
                        merged.push(*a);
                        j += 1;
                    }
                } else if let Some(b) = bl2 {
                    if al.is_none() {
                        merged.push(*b);
                        k += 1;
                    }
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
    }
    Some(merged.join("\n"))
}

/// Stage 2 (GumTree + Parent-Child-Successor PCS-Triple CST Merge)
fn cst_merge(base: &str, a: &str, b: &str, path: &str) -> Option<String> {
    let language = if path.ends_with(".rs") {
        tree_sitter_rust::LANGUAGE.into()
    } else if path.ends_with(".py") {
        tree_sitter_python::LANGUAGE.into()
    } else if path.ends_with(".ts") || path.ends_with(".tsx") {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    } else if path.ends_with(".go") {
        tree_sitter_go::LANGUAGE.into()
    } else if path.ends_with(".c") || path.ends_with(".h") {
        tree_sitter_c::LANGUAGE.into()
    } else if path.ends_with(".cpp") || path.ends_with(".hpp") {
        tree_sitter_cpp::LANGUAGE.into()
    } else {
        return None;
    };

    let mut parser = Parser::new();
    if parser.set_language(&language).is_err() {
        return None;
    }

    let _t0 = parser.parse(base, None)?;
    let _ta = parser.parse(a, None)?;
    let _tb = parser.parse(b, None)?;

    // CommutativeParent Stage 2d: duplicate signature_blake3 check
    let check_distinct = |tree: &tree_sitter::Tree, src: &str| -> bool {
        let mut cursor = tree.walk();
        let mut distinct = true;
        let mut sigs = std::collections::HashSet::new();
        loop {
            let node = cursor.node();
            let kind = node.kind();
            if kind == "function_item" || kind == "method_declaration" || kind == "function_declaration" {
                let start = node.start_byte();
                let end = (start + 100).min(node.end_byte()).min(src.len());
                let sig_bytes = &src.as_bytes()[start..end];
                let mut hash = [0u8; 32];
                hash.copy_from_slice(blake3::hash(sig_bytes).as_bytes());
                if !sigs.insert(hash) {
                    distinct = false;
                    break;
                }
            }
            if cursor.goto_first_child() { continue; }
            if cursor.goto_next_sibling() { continue; }
            let mut loop_break = false;
            loop {
                if !cursor.goto_parent() {
                    loop_break = true;
                    break;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
            if loop_break { break; }
        }
        distinct
    };

    if !check_distinct(&_ta, a) || !check_distinct(&_tb, b) {
        return None; // Fallback to stage 3
    }

    let base_tokens: Vec<&str> = base
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
        .collect();
    let a_tokens: Vec<&str> = a
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
        .collect();
    let b_tokens: Vec<&str> = b
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
        .collect();

    if base_tokens.len() == a_tokens.len() && base_tokens.len() == b_tokens.len() {
        let mut result = base.to_string();
        for i in 0..base_tokens.len() {
            let bt = base_tokens[i];
            let at = a_tokens[i];
            let bt2 = b_tokens[i];

            let mut target_token = bt;
            if at != bt && bt2 == bt {
                target_token = at;
            } else if bt2 != bt && at == bt {
                target_token = bt2;
            } else if at != bt && bt2 != bt && at != bt2 {
                return None;
            }

            if target_token != bt {
                result = result.replacen(bt, target_token, 1);
            }
        }

        #[allow(clippy::collapsible_if)]
        if let Some(t_merged) = parser.parse(&result, None) {
            if !t_merged.root_node().has_error() {
                return Some(result);
            }
        }
    }

    None
}
