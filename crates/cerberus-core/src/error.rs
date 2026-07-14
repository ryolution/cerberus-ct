use thiserror::Error;

pub type Result<T> = std::result::Result<T, CerberusError>;

#[derive(Debug, Error)]
pub enum CerberusError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("certificate parsing error: {0}")]
    CertificateParsing(String),

    #[error("CT source error: {0}")]
    CtSource(String),

    #[error("domain normalization error: {0}")]
    DomainNormalization(String),

    #[error("detection error: {0}")]
    Detection(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("output error: {0}")]
    Output(String),

    #[error("state error: {0}")]
    State(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML serialization error: {0}")]
    Yaml(#[from] yaml_serde::Error),
}
