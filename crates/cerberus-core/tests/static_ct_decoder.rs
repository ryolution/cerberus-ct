use cerberus_core::{
    StaticCtDecodedEntryKind, decode_static_ct_data_tile_bytes,
    decoded_entries_to_certificate_events,
};

const DER_CERT: &[u8] = include_bytes!("fixtures/san_cert.der");

#[test]
fn decodes_static_ct_x509_data_tile_entry() {
    let tile = build_x509_leaf(DER_CERT, 1700000000000);
    let entries = decode_static_ct_data_tile_bytes(&tile, 700).unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].index, 700);
    assert_eq!(entries[0].timestamp_millis, 1700000000000);
    assert_eq!(entries[0].kind, StaticCtDecodedEntryKind::X509);
}

#[test]
fn converts_decoded_static_ct_entries_into_certificate_events() {
    let tile = build_x509_leaf(DER_CERT, 1700000000000);
    let entries = decode_static_ct_data_tile_bytes(&tile, 700).unwrap();
    let decoded = decoded_entries_to_certificate_events(&entries, "integration-log");

    assert_eq!(decoded.entry_count, 1);
    assert_eq!(decoded.event_count, 1);
    assert_eq!(decoded.parse_error_count, 0);
    assert_eq!(decoded.events[0].source_log, "integration-log");
    assert_eq!(decoded.events[0].index, Some(700));
    assert!(
        decoded.events[0]
            .domains
            .iter()
            .any(|domain| domain.as_str() == "paypa1-login.com")
    );
}

#[test]
fn rejects_truncated_static_ct_data_tile() {
    let mut tile = build_x509_leaf(DER_CERT, 1700000000000);
    tile.truncate(16);

    assert!(decode_static_ct_data_tile_bytes(&tile, 0).is_err());
}

fn build_x509_leaf(cert: &[u8], timestamp: u64) -> Vec<u8> {
    let mut tile = Vec::new();
    tile.extend_from_slice(&timestamp.to_be_bytes());
    tile.extend_from_slice(&0u16.to_be_bytes());
    push_vec_u24(&mut tile, cert);
    tile.extend_from_slice(&0u16.to_be_bytes());
    tile.extend_from_slice(&0u16.to_be_bytes());
    tile
}

fn push_vec_u24(output: &mut Vec<u8>, bytes: &[u8]) {
    output.push(((bytes.len() >> 16) & 0xff) as u8);
    output.push(((bytes.len() >> 8) & 0xff) as u8);
    output.push((bytes.len() & 0xff) as u8);
    output.extend_from_slice(bytes);
}
