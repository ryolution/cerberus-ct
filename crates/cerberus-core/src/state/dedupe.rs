use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct DedupeCache {
    seen: HashSet<String>,
}

impl DedupeCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl Into<String>) -> bool {
        self.seen.insert(key.into())
    }

    pub fn contains(&self, key: &str) -> bool {
        self.seen.contains(key)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}
