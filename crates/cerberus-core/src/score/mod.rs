pub mod scorer;
pub mod severity;

pub use scorer::merge_findings;
pub use severity::severity_from_score;
