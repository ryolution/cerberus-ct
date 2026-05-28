use async_trait::async_trait;

use crate::error::Result;
use crate::event::CertificateEvent;

#[async_trait]
pub trait CtSource: Send + Sync {
    async fn next_batch(&mut self) -> Result<Vec<CertificateEvent>>;
}
