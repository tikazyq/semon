use super::*;
use crate::{Store, Versions, parquet_io::read_batches, store::Fault};

fn label(id: &str) -> Label {
    Label {
        id: id.into(),
        target_type: "lane".into(),
        target_id: "lane/work".into(),
        field: "outcome".into(),
        value: "achieved".into(),
        mechanism_text: Some("PRIVATE MECHANISM".into()),
        evidence_step_ids: vec!["origin/claude/native/s/step".into()],
        labeler: "model:fixture".into(),
        taxonomy_version: 2,
        confidence: Some(0.8),
        created_at: 100,
    }
}

fn adjudication() -> Adjudication {
    Adjudication {
        id: "decision".into(),
        label_ids: vec!["assertion".into()],
        target_type: "lane".into(),
        target_id: "lane/work".into(),
        field: "outcome".into(),
        taxonomy_version: 2,
        created_at: 100,
        final_value: "partial".into(),
        adjudicator: "reviewer".into(),
        reason: Some("PRIVATE REASON".into()),
    }
}

#[test]
fn schema_classes_writer_ownership_and_insert_only() {
    let root = tempfile::tempdir().unwrap();
    let mut writer = Writer::open(root.path()).unwrap();
    assert!(matches!(Writer::open(root.path()), Err(Error::WriterBusy)));
    assert_eq!(
        writer
            .connection
            .query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    assert_eq!(
        writer
            .connection
            .query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    for table in TABLES {
        let mut statement = writer
            .connection
            .prepare(&format!("PRAGMA table_info('{}')", table.name))
            .unwrap();
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            columns,
            table
                .columns
                .iter()
                .map(|column| column.name.to_string())
                .collect::<Vec<_>>()
        );
        for column in table.columns {
            let class: String = writer
                .connection
                .query_row(
                    "SELECT class FROM column_class WHERE table_name=?1 AND column_name=?2",
                    params![table.name, column.name],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                class,
                if column.class == Class::Body {
                    "body"
                } else {
                    "categorical"
                }
            );
        }
    }
    assert_eq!(writer.insert_label(&label("assertion")).unwrap(), 1);
    assert_eq!(writer.insert_adjudication(&adjudication()).unwrap(), 2);
    for table in ["label", "adjudication"] {
        assert!(
            writer
                .connection
                .execute(
                    &format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
                    []
                )
                .is_err()
        );
        assert!(
            writer
                .connection
                .execute(&format!("UPDATE {table} SET revision=99"), [])
                .is_err()
        );
        assert!(
            writer
                .connection
                .execute(&format!("DELETE FROM {table}"), [])
                .is_err()
        );
    }
    assert!(writer.insert_label(&label("assertion")).is_err());
    assert_eq!(
        writer
            .connection
            .query_row("SELECT revision FROM durable_state", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert!(
        writer
            .put(
                "lane",
                BTreeMap::from([("title".into(), serde_json::json!("no id"))])
            )
            .is_err()
    );
    let lane = BTreeMap::from([
        ("id".into(), serde_json::json!("work")),
        ("title".into(), serde_json::json!("PRIVATE TITLE")),
        (
            "root_session_id".into(),
            serde_json::json!("origin/claude/native"),
        ),
    ]);
    assert_eq!(writer.put("lane", lane.clone()).unwrap(), 3);
    assert_eq!(writer.put("lane", lane).unwrap(), 4);
    drop(writer);
    assert!(Writer::open(root.path()).is_ok());
}

#[test]
fn mismatched_stamp_refuses_without_mutation() {
    let root = tempfile::tempdir().unwrap();
    let writer = Writer::open(root.path()).unwrap();
    writer
        .connection
        .execute("UPDATE durable_state SET format='unsupported'", [])
        .unwrap();
    drop(writer);
    let path = root.path().join(FILE_NAME);
    let before = std::fs::read(&path).unwrap();
    assert!(Writer::open(root.path()).is_err());
    assert!(backup(root.path(), &root.path().join("copy.sqlite3")).is_err());
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert!(!root.path().join("copy.sqlite3").exists());
}

#[test]
fn adjudication_rejects_mismatched_labels() {
    let root = tempfile::tempdir().unwrap();
    let mut writer = Writer::open(root.path()).unwrap();
    writer.insert_label(&label("assertion")).unwrap();
    for mismatch in 0..6 {
        let mut decision = adjudication();
        match mismatch {
            0 => decision.target_type = "session".into(),
            1 => decision.target_id = "other".into(),
            2 => decision.field = "other".into(),
            3 => decision.taxonomy_version += 1,
            4 => decision.created_at += 1,
            _ => decision.label_ids.push("missing".into()),
        }
        assert!(writer.insert_adjudication(&decision).is_err());
    }
    writer.insert_adjudication(&adjudication()).unwrap();
}

#[test]
fn committed_outbox_survives_failed_publication_and_excludes_bodies() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(FILE_NAME);
    let mut writer = Writer::open(root.path()).unwrap();
    writer.insert_label(&label("assertion")).unwrap();
    writer.insert_adjudication(&adjudication()).unwrap();
    drop(writer); // simulate author exit after durable commit, before export
    let before = std::fs::read(&path).unwrap();
    let store_root = root.path().join("analytics-store");
    let mut store = Store::open(&store_root).unwrap();
    let mut update = Update {
        versions: Versions::default(),
        ..Update::default()
    };
    append_outbox(&path, &mut update).unwrap();
    assert_eq!(update.durable_revision, 2);
    assert_eq!(update.tables[0].batch.num_rows(), 2);
    store.fault = Some(Fault::BeforeRename);
    assert!(store.publish(&update).is_err());
    drop(store);
    let mut store = Store::open(&store_root).unwrap();
    assert_eq!(store.manifest().durable_revision, 0);
    let mut update = Update::default();
    append_outbox(&path, &mut update).unwrap();
    store.publish(&update).unwrap();
    assert_eq!(store.manifest().durable_revision, 2);
    assert!(store.live_map().is_empty()); // lane labels do not need a session
    let file = store.manifest().files_of("fact_label").next().unwrap();
    let batches = read_batches(&store.analytics_dir().join(&file.path), None).unwrap();
    assert_eq!(batches[0].num_rows(), 2);
    let schema = batches[0].schema();
    assert_eq!(
        schema.fields().len(),
        crate::schema::FACT_LABEL.columns.len() + 1
    );
    for name in [
        "mechanism_text",
        "reason",
        "title",
        "hypothesis",
        "guardrails",
        "label_ids",
    ] {
        assert!(schema.index_of(name).is_err());
    }
    let encoded = format!("{:?}", batches);
    assert!(!encoded.contains("PRIVATE"));
    assert!(encoded.contains("human:reviewer"));
    assert!(encoded.contains("adjudication/decision"));
    let mut next = Update {
        durable_revision: 2,
        ..Update::default()
    };
    append_outbox(&path, &mut next).unwrap();
    assert!(next.tables.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    // A fresh analytics build replays the same durable custody read-only.
    let mut rebuild = Update::default();
    append_outbox(&path, &mut rebuild).unwrap();
    assert_eq!(rebuild.tables[0].batch.num_rows(), 2);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn publication_cycles_pick_up_new_author_commits_without_native_changes() {
    struct Input;
    impl crate::AnalyticsInput for Input {
        type Error = std::convert::Infallible;
        fn read_admitted(
            &mut self,
            _: Option<&str>,
            _: crate::InputBudget,
        ) -> std::result::Result<crate::AdmittedBatch, Self::Error> {
            Ok(crate::AdmittedBatch {
                namespace: "origin".into(),
                checkpoint: "cursor".into(),
                complete: true,
                reconciliation: crate::Reconciliation::Incremental,
                changes: vec![],
            })
        }
    }
    let root = tempfile::tempdir().unwrap();
    let mut store = Store::open(&root.path().join("analytics-store")).unwrap();
    let mut writer = Writer::open(root.path()).unwrap();
    writer.insert_label(&label("assertion")).unwrap();
    crate::publish_cycle(
        &mut store,
        &mut Input,
        "origin",
        Versions::default(),
        crate::InputBudget::default(),
    )
    .unwrap();
    assert_eq!(store.manifest().durable_revision, 1);
    writer.insert_adjudication(&adjudication()).unwrap();
    crate::publish_cycle(
        &mut store,
        &mut Input,
        "origin",
        Versions::default(),
        crate::InputBudget::default(),
    )
    .unwrap();
    assert_eq!(store.manifest().durable_revision, 2);
    assert_eq!(
        store
            .manifest()
            .files_of("fact_label")
            .map(|file| file.rows)
            .sum::<u64>(),
        2
    );
    crate::publish_cycle(
        &mut store,
        &mut Input,
        "origin",
        Versions::default(),
        crate::InputBudget::default(),
    )
    .unwrap();
    assert_eq!(
        store
            .manifest()
            .files_of("fact_label")
            .map(|file| file.rows)
            .sum::<u64>(),
        2
    );
}

#[test]
fn bodies_and_online_backup_include_wal_and_preserve_existing_destination() {
    let root = tempfile::tempdir().unwrap();
    let mut writer = Writer::open(root.path()).unwrap();
    writer.insert_label(&label("assertion")).unwrap();
    writer.insert_adjudication(&adjudication()).unwrap();
    writer
        .put(
            "lane",
            BTreeMap::from([
                ("id".into(), serde_json::json!("work")),
                ("title".into(), serde_json::json!("PRIVATE TITLE")),
                (
                    "root_session_id".into(),
                    serde_json::json!("origin/claude/native"),
                ),
            ]),
        )
        .unwrap();
    writer
        .put(
            "intervention",
            BTreeMap::from([
                ("id".into(), serde_json::json!("experiment")),
                ("lever".into(), serde_json::json!("context")),
                ("hypothesis".into(), serde_json::json!("h".repeat(65537))),
                ("primary_metric".into(), serde_json::json!("usd")),
                ("guardrails".into(), serde_json::json!("PRIVATE GUARDRAILS")),
                ("preregistered_at".into(), serde_json::json!(100)),
            ]),
        )
        .unwrap();
    for (uid, text) in [
        ("label/assertion", "PRIVATE MECHANISM"),
        ("adjudication/decision", "PRIVATE REASON"),
        ("lane/work", "PRIVATE TITLE"),
    ] {
        assert_eq!(
            bodies(
                root.path(),
                uid,
                std::time::Instant::now() + std::time::Duration::from_secs(2)
            )
            .unwrap()[0]
                .text,
            text
        );
    }
    let fields = bodies(
        root.path(),
        "intervention/experiment",
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].text.len(), 65536);
    assert!(fields[0].truncated);
    assert!(
        bodies(
            root.path(),
            "lane/missing",
            std::time::Instant::now() + std::time::Duration::from_secs(2)
        )
        .unwrap()
        .is_empty()
    );
    let target = root.path().join("backup.sqlite3");
    backup(root.path(), &target).unwrap();
    let copy = read_connection(&target).unwrap();
    assert_eq!(
        copy.query_row("SELECT count(*) FROM label", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        copy.query_row("SELECT revision FROM durable_state", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        4
    );
    let before = std::fs::read(&target).unwrap();
    assert!(backup(root.path(), &target).is_err());
    assert_eq!(std::fs::read(target).unwrap(), before);
}
