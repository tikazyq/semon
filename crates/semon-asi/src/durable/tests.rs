use std::collections::{BTreeMap, BTreeSet};

use super::*;

fn label(id: &str) -> Label<'_> {
    Label {
        id,
        target_type: "lane",
        target_uid: "lane/example",
        field: "activity",
        value: "plan",
        mechanism_text: Some("private mechanism"),
        evidence_step_ids: &["origin/claude/session/step"],
        labeller: "model:classifier",
        taxonomy_version: 1,
        confidence: Some(0.5),
        created_at: 100,
    }
}

fn adjudication() -> Adjudication<'static> {
    Adjudication {
        id: "a",
        label_ids: &["one", "two"],
        target_type: "lane",
        target_uid: "lane/example",
        field: "activity",
        final_value: "review",
        adjudicator: "author",
        reason: Some("private reason"),
        taxonomy_version: 1,
        created_at: 100,
    }
}

#[test]
fn schema_classifies_every_column_and_only_declared_bodies() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Writer::open(dir.path()).unwrap();
    let db = &writer.connection;
    let columns = db
        .prepare(
            "SELECT m.name, p.name, p.pk FROM sqlite_schema m, pragma_table_info(m.name) p
         WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%'",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((
                (row.get::<_, String>(0)?, row.get::<_, String>(1)?),
                row.get::<_, i32>(2)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()
        .unwrap();
    let classifications = db
        .prepare("SELECT table_name, column_name, class FROM column_class")
        .unwrap()
        .query_map([], |row| {
            Ok((
                (row.get::<_, String>(0)?, row.get::<_, String>(1)?),
                row.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()
        .unwrap();
    assert!(columns.keys().eq(classifications.keys()));
    let ids: BTreeSet<_> = columns
        .iter()
        .filter_map(|((table, column), pk)| (column == "id" && *pk == 1).then_some(table.as_str()))
        .collect();
    assert_eq!(
        ids,
        BTreeSet::from([
            "label",
            "adjudication",
            "link",
            "lane",
            "work_item",
            "change",
            "outcome",
            "intervention",
            "assignment"
        ])
    );
    let bodies: BTreeSet<_> = classifications
        .iter()
        .filter_map(|((table, column), class)| {
            (class == "body").then_some((table.as_str(), column.as_str()))
        })
        .collect();
    assert_eq!(
        bodies,
        BTreeSet::from([
            ("label", "mechanism_text"),
            ("adjudication", "reason"),
            ("lane", "title"),
            ("intervention", "hypothesis"),
            ("intervention", "guardrails")
        ])
    );
    assert_eq!(
        db.pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    assert_eq!(
        db.pragma_query_value(None, "synchronous", |row| row.get::<_, i32>(0))
            .unwrap(),
        2
    );
    assert!(Writer::open(dir.path()).is_err());
    drop(writer);
    assert!(Writer::open(dir.path()).is_ok());
}

#[test]
fn insert_only_guards_and_failed_writes_keep_revision() {
    let dir = tempfile::tempdir().unwrap();
    let mut writer = Writer::open(dir.path()).unwrap();
    assert_eq!(writer.insert_label(&label("one")).unwrap(), 1);
    assert!(writer.insert_label(&label("one")).is_err());
    assert!(writer.insert_adjudication(&adjudication()).is_err());
    assert_eq!(writer.insert_label(&label("two")).unwrap(), 2);
    assert_eq!(writer.insert_adjudication(&adjudication()).unwrap(), 3);
    let db = Connection::open(path(dir.path())).unwrap();
    for sql in [
        "UPDATE label SET value='x'",
        "DELETE FROM label",
        "INSERT OR REPLACE INTO label SELECT * FROM label",
        "UPDATE adjudication SET reason='x'",
        "DELETE FROM adjudication",
        "INSERT OR REPLACE INTO adjudication SELECT * FROM adjudication",
    ] {
        let error = db.execute(sql, []).unwrap_err();
        assert!(error.to_string().contains("insert-only"), "{sql}: {error}");
    }
    let mut lane = Lane {
        id: "example",
        title: "first",
        root_session_id: "session/one",
        work_item_id: None,
    };
    assert_eq!(writer.put_lane(&lane).unwrap(), 4);
    lane.title = "second";
    assert_eq!(writer.put_lane(&lane).unwrap(), 5);
    let (revision, rows) = outbox(dir.path(), 3).unwrap();
    assert_eq!(revision, 5);
    assert!(rows.is_empty());
    assert_eq!(
        db.query_row("SELECT title FROM lane WHERE id='example'", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap(),
        "second"
    );
}

#[test]
fn adjudication_rejects_each_kind_of_disagreement() {
    let dir = tempfile::tempdir().unwrap();
    let mut writer = Writer::open(dir.path()).unwrap();
    writer.insert_label(&label("one")).unwrap();
    for label in [
        Label {
            target_type: "session",
            ..label("other-type")
        },
        Label {
            target_uid: "lane/other",
            ..label("other-target")
        },
        Label {
            field: "outcome",
            ..label("other-field")
        },
        Label {
            taxonomy_version: 2,
            ..label("other-version")
        },
        Label {
            created_at: 200,
            ..label("other-time")
        },
    ] {
        writer.insert_label(&label).unwrap();
        let labels = ["one", label.id];
        let adjudication = Adjudication {
            label_ids: &labels,
            ..adjudication()
        };
        assert!(
            writer.insert_adjudication(&adjudication).is_err(),
            "{}",
            label.id
        );
    }
    assert_eq!(outbox(dir.path(), 0).unwrap().0, 6);
}

#[test]
fn incompatible_store_is_refused_without_rewriting() {
    let dir = tempfile::tempdir().unwrap();
    let mut writer = Writer::open(dir.path()).unwrap();
    writer.insert_label(&label("one")).unwrap();
    writer
        .connection
        .pragma_update(None, "user_version", FORMAT_VERSION + 1)
        .unwrap();
    drop(writer);
    let original = fs::read(path(dir.path())).unwrap();
    assert!(matches!(
        Writer::open(dir.path()),
        Err(Error::DurableFormat)
    ));
    assert!(matches!(outbox(dir.path(), 0), Err(Error::DurableFormat)));
    let backup_path = dir.path().join("copy.sqlite3");
    assert!(matches!(
        backup(dir.path(), &backup_path),
        Err(Error::DurableFormat)
    ));
    assert!(!backup_path.exists());
    assert_eq!(fs::read(path(dir.path())).unwrap(), original);
}
