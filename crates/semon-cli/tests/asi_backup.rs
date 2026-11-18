use std::process::Command;

use rusqlite::Connection;
use semon_asi::durable::{Lane, Writer};

#[test]
fn online_backup_copies_committed_author_data_and_refuses_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path().join("state/index.json");
    let mut writer = Writer::open(&directory.path().join("state/analytics-store")).unwrap();
    writer
        .put_lane(&Lane {
            id: "lane-1",
            title: "private title",
            root_session_id: "session/1",
            work_item_id: None,
        })
        .unwrap();
    let destination = directory.path().join("backup.sqlite3");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_semon"))
            .args(["asi", "backup"])
            .arg(&destination)
            .arg("--cache")
            .arg(&cache)
            .output()
            .unwrap()
    };
    // The author's connection stays open, so committed changes are still in WAL.
    let output = run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let db = Connection::open(&destination).unwrap();
    assert_eq!(
        db.query_row("SELECT title FROM lane WHERE id = 'lane-1'", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap(),
        "private title"
    );
    assert_eq!(
        db.query_row("SELECT revision FROM durable_state", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    drop(db);
    let original = std::fs::read(&destination).unwrap();
    let output = run();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("destination already exists"));
    assert_eq!(std::fs::read(destination).unwrap(), original);
}
