//! Local author-owned state. Publication and body reads use read-only connections.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};

use crate::error::{Error, Result};
use crate::projection::{Cell, Row};

pub const FILE_NAME: &str = "asi-durable.sqlite3";
const APPLICATION_ID: i32 = 0x53454D44;
const FORMAT_VERSION: i32 = 1;

pub fn path(store_root: &Path) -> PathBuf {
    store_root.join(FILE_NAME)
}

/// Author-assigned IDs and categorical fields are supplied by the caller.
/// `created_at` is UTC milliseconds.
pub struct Label<'a> {
    pub id: &'a str,
    pub target_type: &'a str,
    pub target_uid: &'a str,
    pub field: &'a str,
    pub value: &'a str,
    pub mechanism_text: Option<&'a str>,
    pub evidence_step_ids: &'a [&'a str],
    pub labeller: &'a str,
    pub taxonomy_version: i64,
    pub confidence: Option<f64>,
    pub created_at: i64,
}

/// The listed label IDs must all agree with the adjudication's target, field,
/// taxonomy version and UTC millisecond `created_at`.
pub struct Adjudication<'a> {
    pub id: &'a str,
    pub label_ids: &'a [&'a str],
    pub target_type: &'a str,
    pub target_uid: &'a str,
    pub field: &'a str,
    pub final_value: &'a str,
    pub adjudicator: &'a str,
    pub reason: Option<&'a str>,
    pub taxonomy_version: i64,
    pub created_at: i64,
}

/// Holds the exclusive author lock until dropped. All writes use this API.
pub struct Writer {
    connection: Connection,
    _lock: File,
}

impl Writer {
    pub fn open(store_root: &Path) -> Result<Self> {
        crate::store::create_durable_dir(store_root)?;
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(store_root.join("asi-durable.lock"))?;
        match lock.try_lock() {
            Ok(()) => (),
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(Error::invalid(
                    "another process is the durable store writer",
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }

        let path = path(store_root);
        if !exists(&path)? {
            // Publish a complete schema so interrupted initialization cannot be
            // mistaken for an unsupported on-disk format.
            let file = tempfile::NamedTempFile::new_in(store_root)?;
            let mut connection = open(file.path(), OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("durable.sql"))?;
            tx.commit()?;
            connection.close().map_err(|(_, error)| error)?;
            file.as_file().sync_all()?;
            file.persist_noclobber(&path).map_err(|error| error.error)?;
            File::open(store_root)?.sync_all()?;
        }
        let connection = open(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        require_format(&connection)?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if journal_mode != "wal" {
            return Err(Error::invalid("could not enable WAL on durable store"));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        Ok(Self {
            connection,
            _lock: lock,
        })
    }

    pub fn insert_label(&mut self, label: &Label<'_>) -> Result<u64> {
        validate_target(
            label.target_type,
            label.target_uid,
            label.field,
            label.value,
        )?;
        if !label.labeller.split_once(':').is_some_and(|(kind, name)| {
            matches!(kind, "rule" | "model" | "human") && !name.is_empty()
        }) {
            return Err(Error::invalid("invalid durable label labeller"));
        }
        if label
            .confidence
            .is_some_and(|confidence| !(0.0..=1.0).contains(&confidence))
        {
            return Err(Error::invalid("invalid durable label confidence"));
        }
        self.write(label.id, |tx, revision| {
            tx.execute(
                "INSERT INTO label (id, target_type, target_uid, field, value, mechanism_text, evidence_step_ids, labeller, taxonomy_version, confidence, created_at, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![label.id, label.target_type, label.target_uid, label.field, label.value,
                    label.mechanism_text, serde_json::to_string(label.evidence_step_ids)?, label.labeller,
                    label.taxonomy_version, label.confidence, label.created_at, revision],
            )?;
            Ok(())
        })
    }

    pub fn insert_adjudication(&mut self, adjudication: &Adjudication<'_>) -> Result<u64> {
        validate_target(
            adjudication.target_type,
            adjudication.target_uid,
            adjudication.field,
            adjudication.final_value,
        )?;
        if adjudication.label_ids.is_empty() || adjudication.adjudicator.is_empty() {
            return Err(Error::invalid(
                "adjudication requires labels and an adjudicator",
            ));
        }
        self.write(adjudication.id, |tx, revision| {
            let mut statement = tx.prepare(
                "SELECT EXISTS(SELECT 1 FROM label WHERE id = ?1 AND target_type = ?2 AND target_uid = ?3
                 AND field = ?4 AND taxonomy_version = ?5 AND created_at = ?6)",
            )?;
            for id in adjudication.label_ids {
                let agrees: bool = statement.query_row(params![id, adjudication.target_type,
                    adjudication.target_uid, adjudication.field, adjudication.taxonomy_version,
                    adjudication.created_at], |row| row.get(0))?;
                if !agrees {
                    return Err(Error::invalid("adjudication label is missing or disagrees with its target, field, taxonomy version or created_at"));
                }
            }
            tx.execute(
                "INSERT INTO adjudication (id, label_ids, target_type, target_uid, field, final_value, adjudicator, reason, taxonomy_version, created_at, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![adjudication.id, serde_json::to_string(adjudication.label_ids)?,
                    adjudication.target_type, adjudication.target_uid, adjudication.field,
                    adjudication.final_value, adjudication.adjudicator, adjudication.reason,
                    adjudication.taxonomy_version, adjudication.created_at, revision],
            )?;
            Ok(())
        })
    }

    fn write(
        &mut self,
        id: &str,
        write: impl FnOnce(&Transaction<'_>, i64) -> Result<()>,
    ) -> Result<u64> {
        if id.is_empty() || id.contains('\0') {
            return Err(Error::invalid("invalid author-assigned durable row ID"));
        }
        let tx = self.connection.transaction()?;
        let revision = tx.query_row(
            "UPDATE durable_state SET revision = revision + 1 WHERE singleton = 1 RETURNING revision",
            [],
            |row| row.get(0),
        )?;
        let committed_revision =
            u64::try_from(revision).map_err(|_| Error::invalid("negative durable revision"))?;
        write(&tx, revision)?;
        tx.commit()?;
        Ok(committed_revision)
    }
}

// The remaining author-owned tables allow corrections in place. Each typed
// operation replaces the fields for one author-assigned ID in one revision.
macro_rules! sql_column {
    (reference) => {
        "ref"
    };
    ($field:ident) => {
        stringify!($field)
    };
}

macro_rules! author_record {
    ($name:ident<$lifetime:lifetime>, $method:ident, $table:literal, $($field:ident: $type:ty),+ $(,)?) => {
        pub struct $name<$lifetime> {
            pub id: &$lifetime str,
            $(pub $field: $type,)+
        }

        impl Writer {
            pub fn $method(&mut self, record: &$name<'_>) -> Result<u64> {
                self.write(record.id, |tx, _| {
                    tx.execute(
                        concat!("INSERT INTO ", $table, " (id", $(", ", sql_column!($field),)+
                            ") VALUES (:id", $(", :", sql_column!($field),)+
                            ") ON CONFLICT(id) DO UPDATE SET ",
                            "(", $(sql_column!($field), ", ",)+ "id) = (",
                            $("excluded.", sql_column!($field), ", ",)+ "excluded.id)"),
                        params![record.id, $(record.$field,)+],
                    )?;
                    Ok(())
                })
            }
        }
    };
}

author_record!(Link<'a>, put_link, "link", from_type: &'a str, from_id: &'a str,
    change_id: &'a str, method: &'a str, evidence: &'a str, confidence: f64);
author_record!(Lane<'a>, put_lane, "lane", title: &'a str, root_session_id: &'a str,
    work_item_id: Option<&'a str>);
author_record!(WorkItem<'a>, put_work_item, "work_item", tracker: &'a str, reference: &'a str,
    value_class: Option<&'a str>, size: Option<&'a str>, priority: Option<&'a str>,
    opened_at: i64, closed_at: Option<i64>);
author_record!(Change<'a>, put_change, "change", repo: &'a str, kind: &'a str, reference: &'a str,
    opened_at: i64, merged_at: Option<i64>, reverted_at: Option<i64>);
author_record!(Outcome<'a>, put_outcome, "outcome", change_id: &'a str, ci_on_merge: Option<bool>,
    later_fix_change_id: Option<&'a str>, escaped_defect: Option<bool>, survival_30d: Option<bool>,
    window_closed_at: Option<i64>);
author_record!(Intervention<'a>, put_intervention, "intervention", lever: &'a str, hypothesis: &'a str,
    primary_metric: &'a str, guardrails: &'a str, preregistered_at: i64);
author_record!(Assignment<'a>, put_assignment, "assignment", intervention_id: &'a str,
    unit_type: &'a str, unit_id: &'a str, arm: &'a str, assigned_at: i64);

fn validate_target(target_type: &str, target_uid: &str, field: &str, value: &str) -> Result<()> {
    if !crate::schema::TARGET_TYPE.contains(&target_type)
        || target_uid.is_empty()
        || field.is_empty()
        || value.is_empty()
    {
        return Err(Error::invalid(
            "invalid durable label target, field or value",
        ));
    }
    Ok(())
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn open(path: &Path, flags: OpenFlags) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        path,
        flags | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

fn require_format(connection: &Connection) -> Result<()> {
    let application_id: i32 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != APPLICATION_ID || version != FORMAT_VERSION {
        return Err(Error::DurableFormat);
    }
    Ok(())
}

/// Publication reads the counter and the categorical outbox from one snapshot.
/// No body column is selected or passed to the analytics writer.
pub(crate) fn outbox(store_root: &Path, checkpoint: u64) -> Result<(u64, Vec<Row>)> {
    let sqlite_checkpoint = i64::try_from(checkpoint).map_err(|_| {
        Error::invalid("analytics revision checkpoint is outside the SQLite integer range")
    })?;
    let path = path(store_root);
    if !exists(&path)? && checkpoint == 0 {
        return Ok((0, Vec::new()));
    }
    let mut connection = open(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = connection.transaction()?;
    require_format(&tx)?;
    let revision: i64 = tx.query_row(
        "SELECT revision FROM durable_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if revision < sqlite_checkpoint {
        return Err(Error::invalid(
            "durable store is older than the analytics revision checkpoint",
        ));
    }
    let mut statement = tx.prepare(
        "SELECT 'label/' || id, target_type, target_uid, field, value, labeller, taxonomy_version, confidence, created_at, revision
         FROM label WHERE revision > ?1
         UNION ALL
         SELECT 'adjudication/' || id, target_type, target_uid, field, final_value, 'human:' || adjudicator, taxonomy_version, NULL, created_at, revision
         FROM adjudication WHERE revision > ?1",
    )?;
    let rows = statement
        .query_map([sqlite_checkpoint], |row| {
            Ok(Row::from([
                ("label_id", Cell::Text(row.get(0)?)),
                ("target_type", Cell::Text(row.get(1)?)),
                ("target_uid", Cell::Text(row.get(2)?)),
                ("field", Cell::Text(row.get(3)?)),
                ("value", Cell::Text(row.get(4)?)),
                ("labeller", Cell::Text(row.get(5)?)),
                ("taxonomy_version", Cell::Integer(row.get(6)?)),
                ("confidence", Cell::Float(row.get(7)?)),
                ("created_at", Cell::Timestamp(row.get(8)?)),
                ("revision", Cell::Integer(row.get(9)?)),
            ]))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let revision =
        u64::try_from(revision).map_err(|_| Error::invalid("negative durable revision"))?;
    Ok((revision, rows))
}

/// The only durable row kinds with body fields. IDs are bound as SQL values.
#[derive(Clone, Copy)]
pub enum BodyKind {
    Label,
    Adjudication,
    Lane,
    Intervention,
}

impl BodyKind {
    pub fn from_uid(uid: &str) -> Option<(Self, &str)> {
        let (kind, id) = uid.split_once('/')?;
        let kind = match kind {
            "label" => Self::Label,
            "adjudication" => Self::Adjudication,
            "lane" => Self::Lane,
            "intervention" => Self::Intervention,
            _ => return None,
        };
        Some((kind, id))
    }
}

pub struct Body {
    pub part: &'static str,
    pub text: String,
    pub truncated: bool,
}

/// Read only the declared body fields, after the caller admits origin access.
pub fn bodies(store_root: &Path, kind: BodyKind, id: &str, deadline: Instant) -> Result<Vec<Body>> {
    let path = path(store_root);
    if !exists(&path)? {
        return Ok(Vec::new());
    }
    let mut connection = open(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.busy_timeout(Duration::ZERO)?;
    connection.progress_handler(1000, Some(move || Instant::now() >= deadline))?;
    let tx = connection.transaction()?;
    require_format(&tx)?;
    let (table, columns): (_, &[&'static str]) = match kind {
        BodyKind::Label => ("label", &["mechanism_text"]),
        BodyKind::Adjudication => ("adjudication", &["reason"]),
        BodyKind::Lane => ("lane", &["title"]),
        BodyKind::Intervention => ("intervention", &["hypothesis", "guardrails"]),
    };
    let mut bodies = Vec::new();
    for &part in columns {
        let sql = format!(
            "SELECT substr({part},1,65536), length({part})>65536 FROM {table} WHERE id = ?1 AND {part} IS NOT NULL"
        );
        if let Some(body) = tx
            .query_row(&sql, [id], |row| {
                Ok(Body {
                    part,
                    text: row.get(0)?,
                    truncated: row.get(1)?,
                })
            })
            .optional()?
        {
            bodies.push(body);
        }
    }
    Ok(bodies)
}

/// SQLite online backup, with atomic, no-overwrite installation in the
/// destination directory. The resulting file includes private author text.
pub fn backup(store_root: &Path, destination: &Path) -> Result<()> {
    if exists(destination)? {
        return Err(Error::invalid("durable backup destination already exists"));
    }
    let source = open(&path(store_root), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    require_format(&source)?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file = tempfile::NamedTempFile::new_in(parent)?;
    source.backup(rusqlite::MAIN_DB, file.path(), None)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(destination)
        .map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
