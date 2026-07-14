use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use cerberus_core::{FileWatchStateStore, WatchCtState};

#[test]
fn saves_and_loads_watch_ct_state() {
    let path = std::env::temp_dir().join(format!(
        "cerberus-watch-state-{}.json",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let store = FileWatchStateStore::new(&path);
    let mut state = WatchCtState::new("https://example.com/log");
    state.update_position(1024, "root", 3, 1023);
    state.remember_alerted_domain("paypa1-login.com");

    store.save(&state).unwrap();
    let loaded = store.load().unwrap().unwrap();

    assert_eq!(loaded.log_url, "https://example.com/log");
    assert_eq!(loaded.last_checkpoint_size, 1024);
    assert_eq!(loaded.last_checkpoint_root_hash, Some("root".to_string()));
    assert_eq!(loaded.last_scanned_tile_index, Some(3));
    assert_eq!(loaded.last_scanned_entry_index, Some(1023));
    assert!(loaded.has_alerted("PAYPA1-LOGIN.COM"));

    let _ = fs::remove_file(path);
}

#[test]
fn missing_watch_ct_state_returns_none() {
    let path = std::env::temp_dir().join(format!(
        "cerberus-missing-watch-state-{}.json",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let store = FileWatchStateStore::new(path);
    assert!(store.load().unwrap().is_none());
}
