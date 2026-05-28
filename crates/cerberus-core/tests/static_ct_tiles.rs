use cerberus_core::{
    StaticCtClient, StaticCtTilePath, encode_tile_index, latest_data_tile_for_size,
    latest_tree_tile_for_size, partial_tile_width,
};

#[test]
fn encodes_static_ct_tile_indexes() {
    assert_eq!(encode_tile_index(0), "000");
    assert_eq!(encode_tile_index(1), "001");
    assert_eq!(encode_tile_index(1234067), "x001/x234/067");
}

#[test]
fn builds_static_ct_data_tile_paths() {
    let full = StaticCtTilePath::data(12, None).unwrap();
    let partial = StaticCtTilePath::data(273, Some(112)).unwrap();

    assert_eq!(full.path().unwrap(), "tile/data/012");
    assert_eq!(partial.path().unwrap(), "tile/data/273.p/112");
}

#[test]
fn builds_static_ct_tree_tile_paths() {
    let full = StaticCtTilePath::tree(0, 12, None).unwrap();
    let partial = StaticCtTilePath::tree(1, 273, Some(17)).unwrap();

    assert_eq!(full.path().unwrap(), "tile/0/012");
    assert_eq!(partial.path().unwrap(), "tile/1/273.p/17");
}

#[test]
fn calculates_partial_tile_widths_from_checkpoint_size() {
    assert_eq!(partial_tile_width(70000, 0).unwrap(), Some(112));
    assert_eq!(partial_tile_width(70000, 1).unwrap(), Some(17));
    assert_eq!(partial_tile_width(70000, 2).unwrap(), Some(1));
}

#[test]
fn calculates_latest_tile_paths_from_checkpoint_size() {
    let data = latest_data_tile_for_size(70000).unwrap().unwrap();
    let level_one = latest_tree_tile_for_size(70000, 1).unwrap().unwrap();

    assert_eq!(data.path().unwrap(), "tile/data/273.p/112");
    assert_eq!(level_one.path().unwrap(), "tile/1/001.p/17");
}

#[test]
fn builds_static_ct_tile_urls() {
    let client = StaticCtClient::new("https://example.com/log/checkpoint");
    let tile = StaticCtTilePath::data(1234067, None).unwrap();

    assert_eq!(
        client.tile_url(&tile).unwrap(),
        "https://example.com/log/tile/data/x001/x234/067"
    );
}
