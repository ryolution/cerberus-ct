use async_trait::async_trait;

use crate::ct::source::CtSource;
use crate::error::{CerberusError, Result};
use crate::event::CertificateEvent;

#[derive(Debug, Clone)]
pub struct Rfc6962Source {
    pub base_url: String,
}

impl Rfc6962Source {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }
}

#[async_trait]
impl CtSource for Rfc6962Source {
    async fn next_batch(&mut self) -> Result<Vec<CertificateEvent>> {
        Err(CerberusError::CtSource(
            "RFC 6962 fallback is planned for a later milestone".to_string(),
        ))
    }
}
