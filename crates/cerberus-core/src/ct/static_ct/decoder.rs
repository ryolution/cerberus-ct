use serde::{Deserialize, Serialize};

use crate::cert::parser::parse_der_certificate_event;
use crate::ct::static_ct::tiles::{StaticCtTile, StaticCtTileKind};
use crate::error::{CerberusError, Result};
use crate::event::CertificateEvent;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticCtDecodedEntryKind {
    X509,
    Precertificate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCtDecodedEntry {
    pub index: u64,
    pub timestamp_millis: u64,
    pub kind: StaticCtDecodedEntryKind,
    #[serde(skip_serializing)]
    pub certificate_der: Vec<u8>,
    pub certificate_chain_fingerprints: Vec<String>,
    pub extensions_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCtEntryParseError {
    pub index: u64,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCtDecodedEvents {
    pub entry_count: usize,
    pub event_count: usize,
    pub parse_error_count: usize,
    pub events: Vec<CertificateEvent>,
    pub parse_errors: Vec<StaticCtEntryParseError>,
}

pub fn decode_static_ct_data_tile(tile: &StaticCtTile) -> Result<Vec<StaticCtDecodedEntry>> {
    match &tile.path.kind {
        StaticCtTileKind::Data => {}
        StaticCtTileKind::Tree { .. } => {
            return Err(CerberusError::CtSource(
                "Static CT decoder only accepts data tiles".to_string(),
            ));
        }
    }

    let first_index = tile.path.index.saturating_mul(256);
    let entries = decode_static_ct_data_tile_bytes(&tile.bytes, first_index)?;

    if let Some(width) = tile.path.width {
        if entries.len() > width as usize {
            return Err(CerberusError::CtSource(format!(
                "Static CT data tile decoded {} entries but partial width is {}",
                entries.len(),
                width
            )));
        }
    }

    Ok(entries)
}

pub fn decode_static_ct_data_tile_bytes(
    input: &[u8],
    first_index: u64,
) -> Result<Vec<StaticCtDecodedEntry>> {
    let mut reader = BinaryReader::new(input);
    let mut entries = Vec::new();

    while !reader.is_empty() {
        let entry_index = first_index + entries.len() as u64;
        let entry = decode_entry(&mut reader, entry_index)?;
        entries.push(entry);
    }

    Ok(entries)
}

pub fn decoded_entries_to_certificate_events(
    entries: &[StaticCtDecodedEntry],
    source_log: impl Into<String>,
) -> StaticCtDecodedEvents {
    let source_log = source_log.into();
    let mut events = Vec::new();
    let mut parse_errors = Vec::new();

    for entry in entries {
        match parse_der_certificate_event(
            &entry.certificate_der,
            source_log.clone(),
            Some(entry.index),
            entry.timestamp_millis.to_string(),
        ) {
            Ok(event) => events.push(event),
            Err(error) => parse_errors.push(StaticCtEntryParseError {
                index: entry.index,
                error: error.to_string(),
            }),
        }
    }

    StaticCtDecodedEvents {
        entry_count: entries.len(),
        event_count: events.len(),
        parse_error_count: parse_errors.len(),
        events,
        parse_errors,
    }
}

fn decode_entry(reader: &mut BinaryReader<'_>, index: u64) -> Result<StaticCtDecodedEntry> {
    let timestamp_millis = reader.read_u64()?;
    let entry_type = reader.read_u16()?;

    match entry_type {
        0 => decode_x509_entry(reader, index, timestamp_millis),
        1 => decode_precertificate_entry(reader, index, timestamp_millis),
        value => Err(CerberusError::CtSource(format!(
            "unsupported Static CT entry type {value} at log index {index}"
        ))),
    }
}

fn decode_x509_entry(
    reader: &mut BinaryReader<'_>,
    index: u64,
    timestamp_millis: u64,
) -> Result<StaticCtDecodedEntry> {
    let certificate_der = reader.read_vec_u24()?;
    let extensions = reader.read_vec_u16()?;
    let certificate_chain_fingerprints = reader.read_fingerprints()?;

    Ok(StaticCtDecodedEntry {
        index,
        timestamp_millis,
        kind: StaticCtDecodedEntryKind::X509,
        certificate_der,
        certificate_chain_fingerprints,
        extensions_len: extensions.len(),
    })
}

fn decode_precertificate_entry(
    reader: &mut BinaryReader<'_>,
    index: u64,
    timestamp_millis: u64,
) -> Result<StaticCtDecodedEntry> {
    reader.read_exact(32)?;
    reader.read_vec_u24()?;
    let extensions = reader.read_vec_u16()?;
    let certificate_der = reader.read_vec_u24()?;
    let certificate_chain_fingerprints = reader.read_fingerprints()?;

    Ok(StaticCtDecodedEntry {
        index,
        timestamp_millis,
        kind: StaticCtDecodedEntryKind::Precertificate,
        certificate_der,
        certificate_chain_fingerprints,
        extensions_len: extensions.len(),
    })
}

struct BinaryReader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position >= self.input.len()
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(len).ok_or_else(|| {
            CerberusError::CtSource("Static CT decoder position overflow".to_string())
        })?;

        if end > self.input.len() {
            return Err(CerberusError::CtSource(format!(
                "Static CT tile ended unexpectedly at byte {} while reading {} bytes",
                self.position, len
            )));
        }

        let bytes = &self.input[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u24(&mut self) -> Result<usize> {
        let bytes = self.read_exact(3)?;
        Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_exact(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_vec_u16(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u16()? as usize;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_vec_u24(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u24()?;
        if len == 0 {
            return Err(CerberusError::CtSource(
                "Static CT ASN.1 certificate field cannot be empty".to_string(),
            ));
        }
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_fingerprints(&mut self) -> Result<Vec<String>> {
        let len = self.read_u16()? as usize;
        if len % 32 != 0 {
            return Err(CerberusError::CtSource(format!(
                "Static CT certificate chain fingerprint vector length must be a multiple of 32, got {len}"
            )));
        }

        let bytes = self.read_exact(len)?;
        Ok(bytes.chunks_exact(32).map(hex_encode).collect())
    }
}

fn hex_encode(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);

    for byte in input {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const DER_CERT: &[u8] = include_bytes!("../../../tests/fixtures/san_cert.der");

    #[test]
    fn decodes_x509_data_tile_leaf() {
        let tile = build_x509_leaf(DER_CERT, 42, 1700000000000);
        let entries = decode_static_ct_data_tile_bytes(&tile, 42).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].index, 42);
        assert_eq!(entries[0].timestamp_millis, 1700000000000);
        assert_eq!(entries[0].kind, StaticCtDecodedEntryKind::X509);
        assert_eq!(entries[0].certificate_der, DER_CERT);
    }

    #[test]
    fn converts_decoded_entries_to_certificate_events() {
        let tile = build_x509_leaf(DER_CERT, 42, 1700000000000);
        let entries = decode_static_ct_data_tile_bytes(&tile, 42).unwrap();
        let decoded = decoded_entries_to_certificate_events(&entries, "test-log");

        assert_eq!(decoded.entry_count, 1);
        assert_eq!(decoded.event_count, 1);
        assert_eq!(decoded.parse_error_count, 0);
        assert_eq!(decoded.events[0].source_log, "test-log");
        assert_eq!(decoded.events[0].index, Some(42));
        assert!(
            decoded.events[0]
                .domains
                .iter()
                .any(|domain| domain.as_str() == "paypa1-login.com")
        );
    }

    #[test]
    fn decodes_precertificate_leaf_using_embedded_precertificate() {
        let tile = build_precert_leaf(DER_CERT, 9, 1700000000001);
        let entries = decode_static_ct_data_tile_bytes(&tile, 9).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, StaticCtDecodedEntryKind::Precertificate);
        assert_eq!(entries[0].certificate_der, DER_CERT);
        assert_eq!(entries[0].certificate_chain_fingerprints.len(), 1);
    }

    #[test]
    fn rejects_invalid_fingerprint_vector_length() {
        let mut tile = Vec::new();
        push_u64(&mut tile, 1700000000000);
        push_u16(&mut tile, 0);
        push_vec_u24(&mut tile, DER_CERT);
        push_u16(&mut tile, 0);
        push_u16(&mut tile, 31);
        tile.extend_from_slice(&[0u8; 31]);

        assert!(decode_static_ct_data_tile_bytes(&tile, 0).is_err());
    }

    fn build_x509_leaf(cert: &[u8], index: u64, timestamp: u64) -> Vec<u8> {
        let mut tile = Vec::new();
        let _ = index;
        push_u64(&mut tile, timestamp);
        push_u16(&mut tile, 0);
        push_vec_u24(&mut tile, cert);
        push_u16(&mut tile, 0);
        push_u16(&mut tile, 0);
        tile
    }

    fn build_precert_leaf(cert: &[u8], index: u64, timestamp: u64) -> Vec<u8> {
        let mut tile = Vec::new();
        let _ = index;
        push_u64(&mut tile, timestamp);
        push_u16(&mut tile, 1);
        tile.extend_from_slice(&[7u8; 32]);
        push_vec_u24(&mut tile, &[1, 2, 3]);
        push_u16(&mut tile, 0);
        push_vec_u24(&mut tile, cert);
        push_u16(&mut tile, 32);
        tile.extend_from_slice(&[9u8; 32]);
        tile
    }

    fn push_u16(output: &mut Vec<u8>, value: u16) {
        output.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u64(output: &mut Vec<u8>, value: u64) {
        output.extend_from_slice(&value.to_be_bytes());
    }

    fn push_vec_u24(output: &mut Vec<u8>, bytes: &[u8]) {
        output.push(((bytes.len() >> 16) & 0xff) as u8);
        output.push(((bytes.len() >> 8) & 0xff) as u8);
        output.push((bytes.len() & 0xff) as u8);
        output.extend_from_slice(bytes);
    }
}
