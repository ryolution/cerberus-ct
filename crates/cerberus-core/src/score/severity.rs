use crate::finding::Severity;

pub fn severity_from_score(score: u8) -> Severity {
    match score {
        0..=19 => Severity::Info,
        20..=39 => Severity::Low,
        40..=69 => Severity::Medium,
        70..=89 => Severity::High,
        _ => Severity::Critical,
    }
}
