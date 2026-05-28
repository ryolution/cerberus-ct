use crate::config::CerberusConfig;
use crate::error::Result;
use crate::event::DomainObservation;
use crate::finding::Finding;

#[derive(Debug)]
pub struct DetectionContext<'a> {
    config: &'a CerberusConfig,
}

impl<'a> DetectionContext<'a> {
    pub fn new(config: &'a CerberusConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &'a CerberusConfig {
        self.config
    }
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;

    fn detect(
        &self,
        observation: &DomainObservation,
        ctx: &DetectionContext<'_>,
    ) -> Result<Vec<Finding>>;
}
