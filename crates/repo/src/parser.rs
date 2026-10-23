use base::path::PosixPath;
use dashmap::DashMap;
use tree_sitter::{InputEdit, Language, Parser as TsParser, Tree};

pub struct Parser {
    cache: DashMap<(PosixPath, [u8; 32]), Tree>,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

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
        } else if path.ends_with(".ts") || path.ends_with(".tsx") {
            Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
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
