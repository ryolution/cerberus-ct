use cerberus_core::{StaticCtClient, parse_static_ct_checkpoint};

fn root_hash() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode([9u8; 32])
}

#[test]
fn parses_static_ct_checkpoint() {
    let input = format!(
        "cerberus.example/log\n1000\n{}\n\n\u{2014} cerberus.example/log sig\n",
        root_hash()
    );
    let checkpoint = parse_static_ct_checkpoint(&input).unwrap();

    assert_eq!(checkpoint.origin, "cerberus.example/log");
    assert_eq!(checkpoint.size, 1000);
    assert_eq!(checkpoint.root_hash, root_hash());
    assert_eq!(
        checkpoint.signatures,
        vec!["\u{2014} cerberus.example/log sig"]
    );
}

#[test]
fn rejects_static_ct_checkpoint_without_root_hash() {
    let input = "cerberus.example/log\n1000\n";
    assert!(parse_static_ct_checkpoint(input).is_err());
}

#[test]
fn normalizes_static_ct_checkpoint_url() {
    let client = StaticCtClient::new("https://static.example/log/");
    assert_eq!(
        client.checkpoint_url(),
        "https://static.example/log/checkpoint"
    );
}
