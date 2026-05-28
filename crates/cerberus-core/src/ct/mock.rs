use std::collections::VecDeque;

use async_trait::async_trait;

use crate::ct::source::CtSource;
use crate::error::Result;
use crate::event::CertificateEvent;

pub struct MockCtSource {
    batches: VecDeque<Vec<CertificateEvent>>,
}

impl MockCtSource {
    pub fn new(batches: Vec<Vec<CertificateEvent>>) -> Self {
        Self {
            batches: VecDeque::from(batches),
        }
    }

    pub fn demo() -> Result<Self> {
        Ok(Self::new(vec![vec![
            CertificateEvent::new(
                "mock-static-ct",
                ["paypa1-login.com", "github.com", "micr0soft-support.net"],
                "2026-05-28T00:00:00Z",
            )?
            .with_index(1),
            CertificateEvent::new(
                "mock-static-ct",
                ["xn--paypa1-4ve.com", "secure-wallet-example.net"],
                "2026-05-28T00:00:05Z",
            )?
            .with_index(2),
        ]]))
    }
}

#[async_trait]
impl CtSource for MockCtSource {
    async fn next_batch(&mut self) -> Result<Vec<CertificateEvent>> {
        Ok(self.batches.pop_front().unwrap_or_default())
    }
}
