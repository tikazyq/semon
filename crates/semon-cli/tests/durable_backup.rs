use std::process::Command;

#[test]
fn backup_cli_copies_committed_wal_and_refuses_existing_destination() {
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("sessions-index.json");
    let mut writer = semon_asi::durable::Writer::open(root.path()).unwrap();
    writer
        .put(
            "lane",
            serde_json::from_value(serde_json::json!({
                "id":"author-id","title":"private title","root_session_id":"origin/claude/native"
            }))
            .unwrap(),
        )
        .unwrap();
    let destination = root.path().join("backup.sqlite3");
    let output = Command::new(env!("CARGO_BIN_EXE_semon"))
        .args(["asi", "backup"])
        .arg(&destination)
        .arg("--cache")
        .arg(&cache)
        .env("SEMON_PRICING_REFRESH", "off")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let backup = rusqlite::Connection::open(&destination).unwrap();
    assert_eq!(
        backup
            .query_row("SELECT title FROM lane WHERE id='author-id'", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        "private title"
    );
    drop(backup);
    let before = std::fs::read(&destination).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_semon"))
        .args(["asi", "backup"])
        .arg(&destination)
        .arg("--cache")
        .arg(&cache)
        .env("SEMON_PRICING_REFRESH", "off")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(std::fs::read(destination).unwrap(), before);
}
