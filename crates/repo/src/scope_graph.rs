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
}

/// Represents the strict lexical shadowing priority ladder for resolving references.
#[derive(Debug, Clone, PartialEq)]
pub enum ShadowPriority {
    /// Highest priority: inner local block.
    InnerLocalBlock,
    /// Receiver impl or class scope.
    ReceiverImplOrClassScope,
    /// Explicit named import.
    ExplicitNamedImport,
    /// Definition in the same module.
    SameModuleDefinition,
    /// Wildcard import.
    WildcardImport,
    /// Lowest priority: Prelude.
    Prelude,
}

/// A 3-Pass Lexical Scope-Graph for cross-file symbol resolution.
pub struct ScopeGraph {
    /// Map of symbol ID to symbol definitions.
    pub definitions: HashMap<String, SymbolDef>,
}

impl ScopeGraph {
    /// Creates a new, empty `ScopeGraph`.
    pub fn new() -> Self {
        Self {
            definitions: HashMap::new(),
        }
    }
}

impl Default for ScopeGraph {
    fn default() -> Self {
        Self::new()
    }
}
