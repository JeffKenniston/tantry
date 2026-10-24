use crate::FileMutationAnalysis;
use base::platform::RuntimePlatform;
use base::vfs_tree::VfsTree;
use rayon::ThreadPool;

/// Configuration for the RepoEngine.
pub struct RepoEngineConfig {
    /// The runtime platform to govern thread pool limits.
    pub platform: RuntimePlatform,
    /// Path to the SQLite database.
    pub db_path: String,
}

/// The RepoEngine Transactional Orchestrator.
pub struct RepoEngine {
    config: RepoEngineConfig,
    pool: ThreadPool,
}

impl RepoEngine {
    /// Creates a new `RepoEngine` instance with the given configuration.
    pub fn new(config: RepoEngineConfig) -> Result<Self, String> {
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let max_threads = match &config.platform {
            RuntimePlatform::AndroidTermux { .. } => num_cpus.min(4),
            RuntimePlatform::LinuxStandard => num_cpus,
        };

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(max_threads)
            .build()
            .map_err(|e| e.to_string())?;

        Ok(Self { config, pool })
    }

    /// Two-Phase Transactional `sync_workspace`.
    ///
    /// Phase A: Uses the bounded Rayon pool to parse dirty files, extract scope graphs,
    /// compute hashes, and run diagnostics.
    /// Phase B: Single SQLite transaction to batch-upsert data and resolve cross-file edges.
    pub fn sync_workspace(&self, vfs: &VfsTree) -> Result<FileMutationAnalysis, String> {
        // Phase A: Lock-Free Parallel CPU Pass
        // 1. Identify dirty files via Indexer
        let dirty_files = {
            let indexer =
                crate::indexer::Indexer::new(&self.config.db_path).map_err(|e| e.to_string())?;
            indexer.get_dirty_files(vfs).map_err(|e| e.to_string())?
        };

        let dirty_files_vec: Vec<String> = dirty_files.into_iter().collect();

        struct PhaseAResult {
            diags: Vec<crate::CstDiagnostic>,
            defs: Vec<crate::scope_graph::SymbolDef>,
            refs: Vec<crate::scope_graph::SymbolRef>,
            imports: Vec<crate::scope_graph::ImportEdge>,
            complexity: u32,
        }

        let phase_a_results: Vec<PhaseAResult> = self.pool.install(|| {
            use rayon::prelude::*;
            dirty_files_vec
                .into_par_iter()
                .map(|file_path| {
                    let mut diags = Vec::new();
                    let mut defs = Vec::new();
                    let mut refs = Vec::new();
                    let mut imports = Vec::new();
                    let mut complexity = 0;

                    if let Some(file_data) = vfs.get(&file_path) {
                        if let Some(source) = file_data.as_str() {
                            let parser = crate::parser::Parser::new();
                            if let Some(tree) =
                                parser.parse(&file_path, source, file_data.blake3_hash)
                            {
                                diags = crate::linting_hooks::check_cst_diagnostics(
                                    &file_path, &tree, source,
                                );

                                // Real AST queries for scope graph extraction and cyclomatic complexity
                                let mut cursor = tree.walk();
                                let mut reached_root = false;

                                while !reached_root {
                                    let node = cursor.node();
                                    let kind = node.kind();

                                    // Cyclomatic complexity
                                    if matches!(
                                        kind,
                                        "if_expression"
                                            | "if_statement"
                                            | "for_expression"
                                            | "for_statement"
                                            | "while_expression"
                                            | "while_statement"
                                            | "match_expression"
                                            | "case_statement"
                                            | "catch_clause"
                                    ) {
                                        complexity += 1;
                                    }

                                    // Extraction logic for SymbolDef
                                    let scope_kind = match kind {
                                        "mod_item" | "namespace_definition" => {
                                            Some(crate::scope_graph::ScopeKind::Module)
                                        }
                                        "struct_item" | "class_declaration" => {
                                            Some(crate::scope_graph::ScopeKind::StructOrClass)
                                        }
                                        "impl_item" | "interface_declaration" => {
                                            Some(crate::scope_graph::ScopeKind::ImplOrInterface)
                                        }
                                        "function_item"
                                        | "function_declaration"
                                        | "method_declaration" => {
                                            Some(crate::scope_graph::ScopeKind::Function)
                                        }
                                        "block" => Some(crate::scope_graph::ScopeKind::Block),
                                        _ => None,
                                    };

                                    if let Some(sk) = scope_kind {
                                        let mut name = String::new();
                                        // simple heuristic to find name
                                        for child in node.children(&mut tree.walk()) {
                                            if child.kind() == "identifier"
                                                || child.kind() == "type_identifier"
                                                || child.kind() == "name"
                                            {
                                                if let Ok(text) = child.utf8_text(source.as_bytes())
                                                {
                                                    name = text.to_string();
                                                    break;
                                                }
                                            }
                                        }
                                        if name.is_empty()
                                            && sk == crate::scope_graph::ScopeKind::Block
                                        {
                                            name = format!("block_{}", node.start_byte());
                                        }

                                        if !name.is_empty() {
                                            let symbol_id =
                                                crate::scope_graph::ScopeGraph::compute_symbol_id(
                                                    &file_path, &name, &sk,
                                                );

                                            let source_bytes = source.as_bytes();
                                            let max_sig_end = (node.start_byte() + 100)
                                                .min(node.end_byte())
                                                .min(source_bytes.len());
                                            let sig_bytes =
                                                &source_bytes[node.start_byte()..max_sig_end];

                                            let body_end = node.end_byte().min(source_bytes.len());
                                            let body_bytes =
                                                &source_bytes[node.start_byte()..body_end];

                                            let mut signature_blake3 = [0u8; 32];
                                            signature_blake3.copy_from_slice(
                                                blake3::hash(sig_bytes).as_bytes(),
                                            );

                                            let mut body_blake3 = [0u8; 32];
                                            body_blake3.copy_from_slice(
                                                blake3::hash(body_bytes).as_bytes(),
                                            );

                                            defs.push(crate::scope_graph::SymbolDef {
                                                symbol_id,
                                                kind: sk,
                                                signature_blake3,
                                                body_blake3,
                                                file_path: file_path.clone(),
                                                scope_qualified_name: name.clone(),
                                            });
                                        }
                                    }

                                    // References (basic heuristic)
                                    if kind == "identifier" {
                                        if let Ok(text) = node.utf8_text(source.as_bytes()) {
                                            refs.push(crate::scope_graph::SymbolRef {
                                                reference_id: format!(
                                                    "{}_{}",
                                                    file_path,
                                                    node.start_byte()
                                                ),
                                                file_path: file_path.clone(),
                                                name: text.to_string(),
                                                scope_id: format!("{}_global", file_path),
                                            });
                                        }
                                    }

                                    // Imports
                                    if kind == "use_declaration" || kind == "import_statement" {
                                        if let Ok(text) = node.utf8_text(source.as_bytes()) {
                                            imports.push(crate::scope_graph::ImportEdge {
                                                file_path: file_path.clone(),
                                                import_name: text.to_string(),
                                                target_symbol_id: None,
                                                is_wildcard: text.contains('*'),
                                            });
                                        }
                                    }

                                    if cursor.goto_first_child() {
                                        continue;
                                    }

                                    if cursor.goto_next_sibling() {
                                        continue;
                                    }

                                    loop {
                                        if !cursor.goto_parent() {
                                            reached_root = true;
                                            break;
                                        }
                                        if cursor.goto_next_sibling() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    PhaseAResult {
                        diags,
                        defs,
                        refs,
                        imports,
                        complexity,
                    }
                })
                .collect()
        });

        let mut all_diags = Vec::new();
        let mut scope_graph = crate::scope_graph::ScopeGraph::new();
        let mut max_complexity = 0;

        for mut res in phase_a_results {
            all_diags.append(&mut res.diags);
            for d in res.defs {
                scope_graph.definitions.insert(d.symbol_id.clone(), d);
            }
            scope_graph.references.append(&mut res.refs);
            scope_graph.imports.append(&mut res.imports);
            if res.complexity > max_complexity {
                max_complexity = res.complexity;
            }
        }

        // Phase B: Single BEGIN IMMEDIATE SQLite Transaction
        let mut conn =
            rusqlite::Connection::open(&self.config.db_path).map_err(|e| e.to_string())?;

        // Ensure tables exist
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS symbols (
                symbol_id TEXT PRIMARY KEY,
                kind TEXT,
                signature_blake3 BLOB,
                body_blake3 BLOB,
                file_path TEXT,
                scope_qualified_name TEXT
            );
            CREATE TABLE IF NOT EXISTS symbol_edges (
                caller_id TEXT,
                callee_id TEXT,
                call_kind TEXT,
                file_path TEXT
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS symbols_fts USING fts5(
                symbol_id, file_path, scope_qualified_name
            );",
        )
        .map_err(|e| e.to_string())?;

        scope_graph
            .pass_1_local_scope_extraction()
            .map_err(|e| e.to_string())?;
        scope_graph
            .pass_2_import_edge_wiring()
            .map_err(|e| e.to_string())?;
        scope_graph
            .pass_3_reference_resolution()
            .map_err(|e| e.to_string())?;

        let mut centrality = crate::graph::GraphCentrality::new();
        for pref in &scope_graph.references {
            if let Some(target_id) = scope_graph.resolved_references.get(&pref.reference_id) {
                centrality.add_edge(
                    pref.scope_id.clone(),
                    target_id.clone(),
                    "reference".to_string(),
                    pref.file_path.clone(),
                );
            }
        }

        let _katz_map = centrality.compute_katz_centrality_iterative();

        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;

        {
            let mut stmt = tx.prepare(
                "INSERT INTO symbols (symbol_id, kind, signature_blake3, body_blake3, file_path, scope_qualified_name)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(symbol_id) DO UPDATE SET
                    signature_blake3 = excluded.signature_blake3,
                    body_blake3 = excluded.body_blake3"
            ).map_err(|e| e.to_string())?;

            for def in scope_graph.definitions.values() {
                let kind_str = match def.kind {
                    crate::scope_graph::ScopeKind::Module => "Module",
                    crate::scope_graph::ScopeKind::StructOrClass => "StructOrClass",
                    crate::scope_graph::ScopeKind::ImplOrInterface => "ImplOrInterface",
                    crate::scope_graph::ScopeKind::Function => "Function",
                    crate::scope_graph::ScopeKind::Block => "Block",
                };

                stmt.execute(rusqlite::params![
                    def.symbol_id,
                    kind_str,
                    def.signature_blake3,
                    def.body_blake3,
                    def.file_path,
                    def.scope_qualified_name
                ])
                .map_err(|e| e.to_string())?;
            }
        }

        tx.commit().map_err(|e| e.to_string())?;

        let mut indexer =
            crate::indexer::Indexer::new(&self.config.db_path).map_err(|e| e.to_string())?;
        indexer.persist(vfs).map_err(|e| e.to_string())?;

        let mut blast_radius = Vec::new();
        let mut max_risk_score = 0.0_f32;

        for def in scope_graph.definitions.values() {
            let br =
                centrality.ast_blast_radius(&def.symbol_id, vec![def.file_path.clone()], true, 0);
            if br.risk_score > max_risk_score {
                max_risk_score = br.risk_score;
            }
            blast_radius.push(br);
        }

        Ok(FileMutationAnalysis {
            diagnostics: all_diags,
            blast_radius,
            max_risk_score,
            cyclomatic_complexity: max_complexity,
        })
    }

    pub fn on_file_mutated(&self, vfs: &VfsTree) -> Result<FileMutationAnalysis, String> {
        self.sync_workspace(vfs)
    }
}
