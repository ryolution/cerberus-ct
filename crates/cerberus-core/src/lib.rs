pub mod alert;
pub mod cert;
pub mod config;
pub mod ct;
pub mod detect;
pub mod dns;
pub mod domain;
pub mod error;
pub mod event;
pub mod finding;
pub mod output;
pub mod score;
pub mod state;

pub use alert::{DomainAlert, group_findings_by_domain};
pub use config::{CerberusConfig, DnsConfig, OutputConfig, RuleConfig};
pub use ct::{
    CtSource, MockCtSource, StaticCtCheckpoint, StaticCtClient, StaticCtDecodedEntry,
    StaticCtDecodedEntryKind, StaticCtDecodedEvents, StaticCtEntryParseError, StaticCtSource,
    StaticCtTile, StaticCtTileKind, StaticCtTileMetadata, StaticCtTilePath,
    decode_static_ct_data_tile, decode_static_ct_data_tile_bytes,
    decoded_entries_to_certificate_events, encode_tile_index, latest_data_tile_for_size,
    latest_tree_tile_for_size, parse_static_ct_checkpoint, partial_tile_width,
};
pub use detect::{
    BrandDetector, DetectionContext, DetectionEngine, Detector, HomoglyphDetector, KeywordDetector,
    TyposquatDetector,
};
pub use dns::{
    DnsEnrichment, DnsResolver, SystemDnsResolver, TakeoverCandidate, TakeoverFingerprint,
    TakeoverStatus, default_takeover_fingerprints, detect_takeover_candidates,
    enrich_findings_with_dns, enrich_findings_with_dns_and_takeover,
    enrich_findings_with_dns_and_takeover_with_resolver, takeover_findings_from_enrichment,
};
pub use domain::{DomainName, normalize_domain};
pub use error::{CerberusError, Result};
pub use event::{CertificateEvent, DomainObservation};
pub use finding::{Evidence, Finding, Severity};
pub use output::{AlertSink, JsonlSink, SlackSink, WebhookPayload, WebhookSink};
pub use state::{FileWatchStateStore, WatchCtState};
