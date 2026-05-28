use async_trait::async_trait;

use crate::error::Result;
use crate::finding::Finding;

#[async_trait]
pub trait AlertSink: Send + Sync {
    async fn send(&self, finding: &Finding) -> Result<()>;
}
