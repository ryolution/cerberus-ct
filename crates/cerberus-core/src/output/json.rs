use async_trait::async_trait;

use crate::error::Result;
use crate::finding::Finding;
use crate::output::sink::AlertSink;

#[derive(Debug, Default)]
pub struct JsonlSink;

impl JsonlSink {
    pub fn encode(finding: &Finding) -> Result<String> {
        Ok(serde_json::to_string(finding)?)
    }
}

#[async_trait]
impl AlertSink for JsonlSink {
    async fn send(&self, finding: &Finding) -> Result<()> {
        println!("{}", Self::encode(finding)?);
        Ok(())
    }
}
