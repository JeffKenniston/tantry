use base::path::PosixPath;
use std::collections::HashMap;

/// Represents the kind of scope a symbol belongs to.
#[derive(Debug, Clone, PartialEq)]
pub enum ScopeKind {
    /// A module scope.
    Module,
    /// A struct or class scope.
    StructOrClass,
    /// An impl block or interface scope.
    ImplOrInterface,
    /// A function scope.
    Function,
    /// A local block scope.
    Block,
}

/// Represents a definition of a symbol within a scope graph.
#[derive(Debug, Clone, PartialEq)]
pub struct SymbolDef {
    /// The unique identifier for the symbol.
    pub symbol_id: String,
    /// The kind of scope this symbol belongs to.
    pub kind: ScopeKind,
    /// The BLAKE3 digest of the symbol's signature.
    pub signature_blake3: [u8; 32],
    /// The BLAKE3 digest of the symbol's body.
    pub body_blake3: [u8; 32],
    /// The file path where this symbol is defined.
    pub file_path: PosixPath,
    /// The fully qualified name of the symbol within its scope.
    pub scope_qualified_name: String,
    /// Whether this definition is a public trait/interface implementation.
    pub is_public_trait_impl: bool,
}

/// Represents the strict lexical shadowing priority ladder for resolving references.
#[derive(Debug, Clone, PartialEq)]
pub enum ShadowPriority {
    /// Highest priority: inner local block.
    InnerLocalBlock = 6,
    /// Receiver impl or class scope.
    ReceiverImplOrClassScope = 5,
    /// Explicit named import.
    ExplicitNamedImport = 4,
    /// Definition in the same module.
    SameModuleDefinition = 3,
    /// Wildcard import.
    WildcardImport = 2,
    /// Lowest priority: Prelude.
    Prelude = 1,
}

/// A reference to a symbol.
#[derive(Debug, Clone, PartialEq)]
pub struct SymbolRef {
    /// The unique identifier for the reference.
    pub reference_id: String,
    /// The file path where this reference occurs.
    pub file_path: PosixPath,
    /// The name of the symbol being referenced.
    pub name: String,
    /// The scope identifier where this reference occurs.
    pub scope_id: String,
}

/// A vertex representing a specific scope.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopeVertex {
    /// The unique identifier for this scope.
    pub scope_id: String,
    /// The kind of scope.
    pub kind: ScopeKind,
    /// The file path where this scope is defined.
    pub file_path: PosixPath,
}

/// A directed edge representing a parent-child scope relationship.
#[derive(Debug, Clone, PartialEq)]
pub struct ParentEdge {
    /// The ID of the child scope.
    pub child_scope_id: String,
    /// The ID of the parent scope.
    pub parent_scope_id: String,
}

/// An import edge connecting a file to a symbol definition.
#[derive(Debug, Clone, PartialEq)]
pub enum ImportEdge {
    ExplicitNamed {
        file_path: PosixPath,
        local_alias: String,
        target_path: PosixPath,
        target_symbol: String,
        target_symbol_id: Option<String>,
    },
    Wildcard {
        file_path: PosixPath,
        import_name: String,
        target_path: PosixPath,
    }
}

impl ImportEdge {
    pub fn file_path(&self) -> &PosixPath {
        match self {
            ImportEdge::ExplicitNamed { file_path, .. } => file_path,
            ImportEdge::Wildcard { file_path, .. } => file_path,
        }
    }
}

/// Phase 2: A 3-Pass Lexical Scope-Graph for cross-file symbol resolution.
pub struct ScopeGraph {
    /// Map of symbol ID to symbol definitions.
    pub definitions: HashMap<String, SymbolDef>,
    /// List of symbol references to resolve.
    pub references: Vec<SymbolRef>,
    /// List of import edges.
    pub imports: Vec<ImportEdge>,
    /// Map of resolved references (reference_id -> symbol_id).
    pub resolved_references: HashMap<String, String>,
    /// List of scope vertices.
    pub scopes: Vec<ScopeVertex>,
    /// List of parent edges.
    pub parent_edges: Vec<ParentEdge>,
}

impl ScopeGraph {
    /// Creates a new, empty `ScopeGraph`.
    pub fn new() -> Self {
        Self {
            definitions: HashMap::new(),
            references: Vec::new(),
            imports: Vec::new(),
            resolved_references: HashMap::new(),
            scopes: Vec::new(),
            parent_edges: Vec::new(),
        }
    }

    /// Computes a unique symbol ID using BLAKE3.
    pub fn compute_symbol_id(
        file_path: &str,
        scope_qualified_name: &str,
        kind: &ScopeKind,
    ) -> String {
        let input = format!("{}::{}::{:?}", file_path, scope_qualified_name, kind);
        blake3::hash(input.as_bytes()).to_hex().to_string()
    }

    /// Pass 1: Local Scope & Definition Extraction
    pub fn pass_1_local_scope_extraction(&mut self) -> Result<(), base::error::ExtensionError> {
        let mut updates = Vec::new();
        for (id, def) in &self.definitions {
            let expected_id =
                Self::compute_symbol_id(def.file_path.as_str(), &def.scope_qualified_name, &def.kind);
            if *id != expected_id {
                updates.push((id.clone(), expected_id));
            }
        }
        for (old_id, new_id) in updates {
            if let Some(mut def) = self.definitions.remove(&old_id) {
                def.symbol_id = new_id.clone();
                self.definitions.insert(new_id, def);
            }
        }
        Ok(())
    }

    /// Pass 2: Import & Export Edge Wiring
    pub fn pass_2_import_edge_wiring(&mut self) -> Result<(), base::error::ExtensionError> {
        for import in self.imports.iter_mut() {
            match import {
                ImportEdge::ExplicitNamed { target_symbol_id, target_symbol, target_path, .. } => {
                    if target_symbol_id.is_none() {
                        for def in self.definitions.values() {
                            if def.scope_qualified_name.ends_with(target_symbol.as_str()) {
                                *target_symbol_id = Some(def.symbol_id.clone());
                                *target_path = def.file_path.clone();
                                break;
                            }
                        }
                    }
                }
                ImportEdge::Wildcard { import_name, target_path, .. } => {
                    let prefix = import_name.trim_end_matches('*').trim_end_matches("::").trim();
                    for def in self.definitions.values() {
                        if def.scope_qualified_name.ends_with(prefix) || def.file_path.contains(prefix) {
                            *target_path = def.file_path.clone();
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Pass 3: Priority-Shadowed Reference Resolution
    pub fn pass_3_reference_resolution(&mut self) -> Result<(), base::error::ExtensionError> {
        for pref in &self.references {
            let mut best_match = None;
            let mut best_priority = 0;

            for def in self.definitions.values() {
                if def.scope_qualified_name.ends_with(&pref.name) {
                    let mut priority = 0;

                    if def.file_path == pref.file_path {
                        if def.kind == ScopeKind::Block {
                            priority = ShadowPriority::InnerLocalBlock as u8;
                        } else if def.kind == ScopeKind::ImplOrInterface {
                            priority = ShadowPriority::ReceiverImplOrClassScope as u8;
                        } else {
                            priority = ShadowPriority::SameModuleDefinition as u8;
                        }
                    } else {
                        for imp in &self.imports {
                            if imp.file_path() == &pref.file_path {
                                match imp {
                                    ImportEdge::ExplicitNamed { target_symbol_id, .. } => {
                                        if target_symbol_id.as_ref() == Some(&def.symbol_id) {
                                            priority = ShadowPriority::ExplicitNamedImport as u8;
                                        }
                                    }
                                    ImportEdge::Wildcard { target_path, .. } => {
                                        if def.file_path == *target_path {
                                            priority = ShadowPriority::WildcardImport as u8;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if priority == 0 {
                        priority = ShadowPriority::Prelude as u8;
                    }

                    if priority > best_priority {
                        best_priority = priority;
                        best_match = Some(def.symbol_id.clone());
                    }
                }
            }

            if let Some(sym_id) = best_match {
                self.resolved_references
                    .insert(pref.reference_id.clone(), sym_id);
            }
        }
        Ok(())
    }
}

impl Default for ScopeGraph {
    fn default() -> Self {
        Self::new()
    }
}

fn walk_signature_tokens(node: tree_sitter::Node<'_>, source: &[u8], hasher: &mut blake3::Hasher) {
    if node.child_count() == 0 {
        if !node.kind().contains("comment") {
            if let Ok(text) = node.utf8_text(source) {
                hasher.update(b" ");
                hasher.update(text.as_bytes());
            }
        }
        return;
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            let field_name = cursor.field_name();
            let kind = child.kind();

            if field_name == Some("body")
                || kind == "block"
                || kind == "declaration_list"
                || kind == "field_declaration_list"
                || kind == "statement_block"
                || kind == "compound_statement"
                || kind.contains("comment")
            {
                // skip
            } else {
                walk_signature_tokens(child, source, hasher);
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn walk_body_tokens(node: tree_sitter::Node<'_>, source: &[u8], hasher: &mut blake3::Hasher) {
    if node.child_count() == 0 {
        if !node.kind().contains("comment") {
            if let Ok(text) = node.utf8_text(source) {
                hasher.update(b" ");
                hasher.update(text.as_bytes());
            }
        }
        return;
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind().contains("comment") {
                // skip
            } else {
                walk_body_tokens(child, source, hasher);
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

/// Computes a normalized BLAKE3 hash of a node's signature (excluding its body).
pub fn compute_normalized_signature_blake3(node: tree_sitter::Node<'_>, source: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tantry:sig:v3:");
    hasher.update(node.kind().as_bytes());

    walk_signature_tokens(node, source, &mut hasher);

    *hasher.finalize().as_bytes()
}

/// Computes a normalized BLAKE3 hash of a node's body.
pub fn compute_normalized_body_blake3(node: tree_sitter::Node<'_>, source: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tantry:body:v3:");

    let mut body_node = node.child_by_field_name("body");

    if body_node.is_none() {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let kind = child.kind();
            if kind == "block"
                || kind == "statement_block"
                || kind == "compound_statement"
                || kind == "declaration_list"
                || kind == "field_declaration_list"
            {
                body_node = Some(child);
                break;
            }
        }
    }

    if let Some(body) = body_node {
        walk_body_tokens(body, source, &mut hasher);
    }

    *hasher.finalize().as_bytes()
}
