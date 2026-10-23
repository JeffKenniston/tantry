use base::path::PosixPath;
use dashmap::DashMap;
use tree_sitter::{InputEdit, Language, Parser as TsParser, Point, Tree};

/// An incremental `tree-sitter` parser for parsing syntax trees.
pub struct Parser {
    cache: DashMap<(PosixPath, [u8; 32]), Tree>,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    /// Creates a new incremental `Parser` with an empty cache.
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

    /// Parses the source code using the language determined by the file path.
    /// Returns `Some(Tree)` if successful, or `None` if the language is unsupported.
    pub fn parse(&self, path: &str, source: &str, hash: [u8; 32]) -> Option<Tree> {
        let key = (path.to_string(), hash);
        if let Some(cached_tree) = self.cache.get(&key) {
            return Some(cached_tree.clone());
        }

        let mut parser = TsParser::new();
        let language = self.get_language(path)?;
        parser.set_language(&language).ok()?;

        let tree = parser.parse(source, None)?;
        self.cache.insert(key, tree.clone());
        Some(tree)
    }

    /// Helper to convert a byte index to a Point by iterating over bytes, avoiding UTF-8 panics.
    fn byte_to_point(source: &str, byte_index: usize) -> Point {
        let bytes = source.as_bytes();
        let limit = byte_index.min(bytes.len());
        let mut row = 0;
        let mut column = 0;
        for &b in &bytes[..limit] {
            if b == b'\n' {
                row += 1;
                column = 0;
            } else {
                column += 1;
            }
        }
        Point::new(row, column)
    }

    /// Computes the `InputEdit` and calls `edit_and_reparse`.
    #[allow(clippy::too_many_arguments)]
    pub fn edit_file(
        &self,
        path: &str,
        old_hash: [u8; 32],
        new_hash: [u8; 32],
        old_source: &str,
        new_source: &str,
        start_byte: usize,
        old_end_byte: usize,
        new_end_byte: usize,
    ) -> Option<Tree> {
        let start_position = Self::byte_to_point(old_source, start_byte);
        let old_end_position = Self::byte_to_point(old_source, old_end_byte);
        let new_end_position = Self::byte_to_point(new_source, new_end_byte);

        let edit = InputEdit {
            start_byte,
            old_end_byte,
            new_end_byte,
            start_position,
            old_end_position,
            new_end_position,
        };

        self.edit_and_reparse(path, old_hash, new_hash, new_source, &edit)
    }

    /// Edits an existing syntax tree (cached by `old_hash`) according to the `InputEdit`,
    /// then reparses incrementally, yielding a new cached tree (associated with `new_hash`).
    pub fn edit_and_reparse(
        &self,
        path: &str,
        old_hash: [u8; 32],
        new_hash: [u8; 32],
        source: &str,
        edit: &InputEdit,
    ) -> Option<Tree> {
        let old_key = (path.to_string(), old_hash);
        let mut old_tree = {
            let entry = self.cache.get(&old_key)?;
            entry.clone()
        };

        old_tree.edit(edit);

        let mut parser = TsParser::new();
        let language = self.get_language(path)?;
        parser.set_language(&language).ok()?;

        let new_tree = parser.parse(source, Some(&old_tree))?;

        let new_key = (path.to_string(), new_hash);
        self.cache.insert(new_key, new_tree.clone());

        Some(new_tree)
    }

    fn get_language(&self, path: &str) -> Option<Language> {
        if path.ends_with(".rs") {
            Some(tree_sitter_rust::LANGUAGE.into())
        } else if path.ends_with(".py") {
            Some(tree_sitter_python::LANGUAGE.into())
        } else if path.ends_with(".ts") {
            Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        } else if path.ends_with(".tsx") {
            Some(tree_sitter_typescript::LANGUAGE_TSX.into())
        } else if path.ends_with(".go") {
            Some(tree_sitter_go::LANGUAGE.into())
        } else if path.ends_with(".c") || path.ends_with(".h") {
            Some(tree_sitter_c::LANGUAGE.into())
        } else if path.ends_with(".cpp") || path.ends_with(".hpp") || path.ends_with(".cc") {
            Some(tree_sitter_cpp::LANGUAGE.into())
        } else {
            None
        }
    }
}
