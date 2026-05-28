pub mod cname;
pub mod fingerprints;
pub mod resolver;
pub mod takeover;

pub use cname::CnameChain;
pub use fingerprints::{TakeoverFingerprint, default_takeover_fingerprints};
pub use resolver::{
    DisabledDnsResolver, DnsEnrichment, DnsResolver, SystemDnsResolver, enrich_findings_with_dns,
    enrich_findings_with_dns_and_takeover, enrich_findings_with_dns_and_takeover_with_resolver,
    enrich_findings_with_resolver,
};
pub use takeover::{
    TakeoverCandidate, TakeoverStatus, detect_takeover_candidates,
    takeover_findings_from_enrichment,
};
