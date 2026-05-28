use cerberus_core::{StaticCtClient, parse_static_ct_checkpoint};

#[test]
fn parses_static_ct_checkpoint() {
    let input = "cerberus.example/log\n1000\nYWJjZGVmZw==\n\ncerberus.example/log+key sig\n";
    let checkpoint = parse_static_ct_checkpoint(input).unwrap();

    assert_eq!(checkpoint.origin, "cerberus.example/log");
    assert_eq!(checkpoint.size, 1000);
    assert_eq!(checkpoint.root_hash, "YWJjZGVmZw==");
    assert_eq!(checkpoint.signatures, vec!["cerberus.example/log+key sig"]);
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
