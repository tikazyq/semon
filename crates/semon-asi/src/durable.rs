//! Author-owned, non-rebuildable state. Analytics and body readers open this file
//! read-only; only `Writer` creates it or changes author records.
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params, types::Value};
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    projection::{Cell, Row},
    store::{TableBatch, Update},
};

pub const FILE_NAME: &str = "asi-durable.sqlite3";
pub const FORMAT: &str = "semon-asi-durable-1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    Categorical,
    Body,
}

#[derive(Clone, Copy, Debug)]
pub struct Column {
    pub name: &'static str,
    pub declaration: &'static str,
    pub class: Class,
}

#[derive(Clone, Copy, Debug)]
pub struct Table {
    pub name: &'static str,
    pub columns: &'static [Column],
}

macro_rules! table {
    ($name:literal, $( $column:literal => $declaration:literal, $class:ident );* $(;)?) => {
        Table { name: $name, columns: &[
            Column { name: "id", declaration: "TEXT PRIMARY KEY NOT NULL CHECK(length(id)>0)", class: Class::Categorical },
            Column { name: "revision", declaration: "INTEGER NOT NULL CHECK(revision>0)", class: Class::Categorical },
            $(Column { name: $column, declaration: $declaration, class: Class::$class },)*
        ] }
    }
}

/// The declarations are also persisted in `column_class`. No wildcard projection
/// of these tables is permitted at the analytics boundary.
pub const TABLES: &[Table] = &[
    table!("label",
        "target_type" => "TEXT NOT NULL", Categorical;
        "target_id" => "TEXT NOT NULL", Categorical;
        "field" => "TEXT NOT NULL", Categorical;
        "value" => "TEXT NOT NULL", Categorical;
        "mechanism_text" => "TEXT", Body;
        "evidence_step_ids" => "TEXT NOT NULL", Categorical;
        "labeler" => "TEXT NOT NULL", Categorical;
        "taxonomy_version" => "INTEGER NOT NULL CHECK(taxonomy_version>=0)", Categorical;
        "confidence" => "REAL CHECK(confidence>=0 AND confidence<=1)", Categorical;
        "created_at" => "INTEGER NOT NULL", Categorical;
    ),
    table!("adjudication",
        "label_ids" => "TEXT NOT NULL", Categorical;
        "target_type" => "TEXT NOT NULL", Categorical;
        "target_id" => "TEXT NOT NULL", Categorical;
        "field" => "TEXT NOT NULL", Categorical;
        "taxonomy_version" => "INTEGER NOT NULL CHECK(taxonomy_version>=0)", Categorical;
        "created_at" => "INTEGER NOT NULL", Categorical;
        "final_value" => "TEXT NOT NULL", Categorical;
        "adjudicator" => "TEXT NOT NULL", Categorical;
        "reason" => "TEXT", Body;
    ),
    table!("link",
        "from_type" => "TEXT NOT NULL", Categorical;
        "from_id" => "TEXT NOT NULL", Categorical;
        "change_id" => "TEXT NOT NULL", Categorical;
        "method" => "TEXT NOT NULL", Categorical;
        "evidence" => "TEXT NOT NULL", Categorical;
        "confidence" => "REAL CHECK(confidence>=0 AND confidence<=1)", Categorical;
    ),
    table!("lane",
        "title" => "TEXT", Body;
        "root_session_id" => "TEXT NOT NULL", Categorical;
        "work_item_id" => "TEXT", Categorical;
    ),
    table!("work_item",
        "tracker" => "TEXT NOT NULL", Categorical;
        "ref" => "TEXT NOT NULL", Categorical;
        "value_class" => "TEXT", Categorical;
        "size" => "TEXT", Categorical;
        "priority" => "TEXT", Categorical;
        "opened_at" => "INTEGER", Categorical;
        "closed_at" => "INTEGER", Categorical;
    ),
    table!("change",
        "repo" => "TEXT NOT NULL", Categorical;
        "kind" => "TEXT NOT NULL", Categorical;
        "ref" => "TEXT NOT NULL", Categorical;
        "opened_at" => "INTEGER", Categorical;
        "merged_at" => "INTEGER", Categorical;
        "reverted_at" => "INTEGER", Categorical;
    ),
    table!("outcome",
        "change_id" => "TEXT NOT NULL", Categorical;
        "ci_on_merge" => "TEXT", Categorical;
        "later_fix_change_id" => "TEXT", Categorical;
        "escaped_defect" => "INTEGER CHECK(escaped_defect IN (0,1))", Categorical;
        "survival_30d" => "INTEGER CHECK(survival_30d IN (0,1))", Categorical;
        "window_closed_at" => "INTEGER", Categorical;
    ),
    table!("intervention",
        "lever" => "TEXT NOT NULL", Categorical;
        "hypothesis" => "TEXT", Body;
        "primary_metric" => "TEXT NOT NULL", Categorical;
        "guardrails" => "TEXT", Body;
        "preregistered_at" => "INTEGER NOT NULL", Categorical;
    ),
    table!("assignment",
        "intervention_id" => "TEXT NOT NULL", Categorical;
        "unit_type" => "TEXT NOT NULL", Categorical;
        "unit_id" => "TEXT NOT NULL", Categorical;
        "arm" => "TEXT NOT NULL", Categorical;
        "assigned_at" => "INTEGER NOT NULL", Categorical;
    ),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Label {
    pub id: String,
    pub target_type: String,
    pub target_id: String,
    pub field: String,
    pub value: String,
    pub mechanism_text: Option<String>,
    pub evidence_step_ids: Vec<String>,
    pub labeler: String,
    pub taxonomy_version: i64,
    pub confidence: Option<f64>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Adjudication {
    pub id: String,
    pub label_ids: Vec<String>,
    pub target_type: String,
    pub target_id: String,
    pub field: String,
    pub taxonomy_version: i64,
    pub created_at: i64,
    pub final_value: String,
    pub adjudicator: String,
    pub reason: Option<String>,
}

/// Values for the other author-owned entities. Column names must match `TABLES`;
/// the caller supplies every required field, including the independent `id`.
/// Lists are stored as JSON, timestamps as UTC milliseconds.
pub type Fields = BTreeMap<String, serde_json::Value>;

pub struct Writer {
    connection: Connection,
    _lock: File,
}

fn read_connection(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    require_format(&connection)?;
    Ok(connection)
}

fn require_format(connection: &Connection) -> Result<()> {
    let format: String = connection
        .query_row(
            "SELECT format FROM durable_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            let error = Error::from(error);
            if error.is_operational() {
                error
            } else {
                Error::invalid("unsupported durable format; preserve or back up the durable store")
            }
        })?;
    if format != FORMAT {
        return Err(Error::invalid(
            "unsupported durable format; preserve or back up the durable store",
        ));
    }
    Ok(())
}

impl Writer {
    /// The parent is the trusted origin state directory, not analytics-store.
    /// Hold one author writer for its entire lifetime; analytics uses a separate
    /// read-only connection and never acquires this writer.
    pub fn open(state: &Path) -> Result<Self> {
        let path = state.join(FILE_NAME);
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("asi-durable.lock"))?;
        crate::store::lock_file(&lock, true)?;
        let exists = match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => true,
            Ok(_) => return Err(Error::invalid("durable store must be a regular file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        // Refuse unsupported custody before opening it writable (even PRAGMAs
        // that change journalling must not run on a mismatched file).
        if exists {
            drop(read_connection(&path)?);
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if !exists {
            drop(options.open(&path)?);
        }
        let mut connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        if !exists {
            let tx = connection.transaction()?;
            tx.execute_batch("CREATE TABLE durable_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),format TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>=0)); CREATE TABLE column_class(table_name TEXT NOT NULL,column_name TEXT NOT NULL,class TEXT NOT NULL CHECK(class IN ('categorical','body')),PRIMARY KEY(table_name,column_name));")?;
            tx.execute("INSERT INTO durable_state VALUES(1,?1,0)", [FORMAT])?;
            for table in TABLES {
                let columns = table
                    .columns
                    .iter()
                    .map(|column| format!("\"{}\" {}", column.name, column.declaration))
                    .collect::<Vec<_>>()
                    .join(",");
                tx.execute_batch(&format!("CREATE TABLE \"{}\"({columns});", table.name))?;
                for column in table.columns {
                    tx.execute(
                        "INSERT INTO column_class VALUES(?1,?2,?3)",
                        params![
                            table.name,
                            column.name,
                            if column.class == Class::Body {
                                "body"
                            } else {
                                "categorical"
                            }
                        ],
                    )?;
                }
            }
            for table in ["label", "adjudication"] {
                tx.execute_batch(&format!("CREATE INDEX {table}_revision ON {table}(revision); CREATE TRIGGER {table}_no_replace BEFORE INSERT ON {table} WHEN EXISTS(SELECT 1 FROM {table} WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'durable assertions are insert-only'); END;"))?;
                for operation in ["UPDATE", "DELETE"] {
                    tx.execute_batch(&format!("CREATE TRIGGER {table}_no_{operation} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'durable assertions are insert-only'); END;"))?;
                }
            }
            tx.commit()?;
            File::open(state)?.sync_all()?;
        }
        Ok(Self {
            connection,
            _lock: lock,
        })
    }

    pub fn insert_label(&mut self, label: &Label) -> Result<u64> {
        validate_target(
            &label.target_type,
            &label.target_id,
            &label.field,
            label.taxonomy_version,
        )?;
        if !["rule:", "model:", "human:"].iter().any(|prefix| {
            label
                .labeler
                .strip_prefix(*prefix)
                .is_some_and(|name| !name.is_empty())
        }) || label
            .confidence
            .is_some_and(|n| !n.is_finite() || !(0.0..=1.0).contains(&n))
        {
            return Err(Error::invalid(
                "invalid durable label authorship or confidence",
            ));
        }
        self.write("label", object(label)?, false)
    }

    pub fn insert_adjudication(&mut self, decision: &Adjudication) -> Result<u64> {
        validate_target(
            &decision.target_type,
            &decision.target_id,
            &decision.field,
            decision.taxonomy_version,
        )?;
        if decision.label_ids.is_empty() || decision.adjudicator.is_empty() {
            return Err(Error::invalid(
                "adjudication requires labels and an adjudicator",
            ));
        }
        // Labels are immutable and this is the sole writer, so validation remains
        // true through the following insert transaction.
        for id in &decision.label_ids {
            let target = self.connection.query_row("SELECT target_type,target_id,field,taxonomy_version,created_at FROM label WHERE id=?1", [id], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?))).optional()?;
            if target
                != Some((
                    decision.target_type.clone(),
                    decision.target_id.clone(),
                    decision.field.clone(),
                    decision.taxonomy_version,
                    decision.created_at,
                ))
            {
                return Err(Error::invalid(
                    "adjudication labels disagree on target, field, taxonomy version or created_at",
                ));
            }
        }
        self.write("adjudication", object(decision)?, false)
    }

    /// Insert or replace the current fields of a mutable author-owned entity.
    /// Labels and adjudications must use their typed insert-only APIs.
    pub fn put(&mut self, table: &str, fields: Fields) -> Result<u64> {
        if matches!(table, "label" | "adjudication") {
            return Err(Error::invalid("assertions require the insert-only API"));
        }
        self.write(table, fields, true)
    }

    fn write(&mut self, name: &str, fields: Fields, upsert: bool) -> Result<u64> {
        let table = TABLES
            .iter()
            .find(|table| table.name == name)
            .ok_or_else(|| Error::invalid("unknown durable table"))?;
        if fields
            .get("id")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
            || fields.keys().any(|name| {
                name == "revision" || !table.columns.iter().any(|column| column.name == name)
            })
        {
            return Err(Error::invalid(
                "durable records require an author-assigned id and declared columns",
            ));
        }
        let tx = self.connection.transaction()?;
        let revision: i64 = tx.query_row(
            "UPDATE durable_state SET revision=revision+1 WHERE singleton=1 RETURNING revision",
            [],
            |row| row.get(0),
        )?;
        let mut names = vec!["\"revision\"".to_owned()];
        let mut values = vec![Value::Integer(revision)];
        for (name, value) in &fields {
            names.push(format!("\"{name}\""));
            values.push(match value {
                serde_json::Value::Null => Value::Null,
                serde_json::Value::Bool(value) => Value::Integer(i64::from(*value)),
                serde_json::Value::Number(value) => {
                    if let Some(value) = value.as_i64() {
                        Value::Integer(value)
                    } else {
                        Value::Real(
                            value
                                .as_f64()
                                .ok_or_else(|| Error::invalid("invalid durable number"))?,
                        )
                    }
                }
                serde_json::Value::String(value) => Value::Text(value.clone()),
                serde_json::Value::Array(_) => Value::Text(serde_json::to_string(value)?),
                serde_json::Value::Object(_) => {
                    return Err(Error::invalid("durable fields cannot contain objects"));
                }
            });
        }
        let placeholders = vec!["?"; names.len()].join(",");
        let conflict = if upsert {
            format!(
                " ON CONFLICT(id) DO UPDATE SET {}",
                names
                    .iter()
                    .filter(|name| name.as_str() != "\"id\"")
                    .map(|name| format!("{name}=excluded.{name}"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else {
            String::new()
        };
        tx.execute(
            &format!(
                "INSERT INTO \"{}\"({}) VALUES({placeholders}){conflict}",
                table.name,
                names.join(",")
            ),
            rusqlite::params_from_iter(values),
        )?;
        tx.commit()?;
        Ok(revision as u64)
    }
}

fn object(value: &impl Serialize) -> Result<Fields> {
    Ok(serde_json::from_value(serde_json::to_value(value)?)?)
}

fn validate_target(kind: &str, id: &str, field: &str, taxonomy: i64) -> Result<()> {
    if !crate::schema::TARGET_TYPE.contains(&kind)
        || id.is_empty()
        || field.is_empty()
        || taxonomy < 0
    {
        return Err(Error::invalid(
            "invalid durable label target, field or taxonomy version",
        ));
    }
    Ok(())
}

/// Add the read-only durable outbox snapshot to the same atomic manifest update
/// as native projections. A later author commit remains above this checkpoint.
pub(crate) fn append_outbox(path: &Path, update: &mut Update) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound && update.durable_revision == 0 =>
        {
            return Ok(());
        }
        Err(error) => return Err(error.into()),
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            return Err(Error::invalid("durable store must be a regular file"));
        }
        Ok(_) => {}
    }
    let mut connection = read_connection(path)?;
    let tx = connection.transaction()?;
    let revision: i64 = tx.query_row(
        "SELECT revision FROM durable_state WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if revision < 0 || (revision as u64) < update.durable_revision {
        return Err(Error::invalid("durable revision went backwards"));
    }
    let after = i64::try_from(update.durable_revision)
        .map_err(|_| Error::invalid("invalid durable checkpoint"))?;
    let mut statement = tx.prepare("SELECT 'label/'||id,target_type,target_id,field,value,labeler,taxonomy_version,confidence,created_at,revision FROM label WHERE revision>?1 UNION ALL SELECT 'adjudication/'||id,target_type,target_id,field,final_value,'human:'||adjudicator,taxonomy_version,NULL,created_at,revision FROM adjudication WHERE revision>?1 ORDER BY revision")?;
    let rows = statement
        .query_map([after], |row| {
            let mut output = Row::new();
            for (index, name) in [
                "label_id",
                "target_type",
                "target_uid",
                "field",
                "value",
                "labeller",
            ]
            .into_iter()
            .enumerate()
            {
                output.insert(name, Cell::Text(Some(row.get(index)?)));
            }
            output.insert("taxonomy_version", Cell::Integer(Some(row.get(6)?)));
            output.insert("confidence", Cell::Float(row.get(7)?));
            output.insert("created_at", Cell::Timestamp(Some(row.get(8)?)));
            output.insert("revision", Cell::Integer(Some(row.get(9)?)));
            Ok(output)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !rows.is_empty() {
        update.tables.push(TableBatch {
            table: &crate::schema::FACT_LABEL,
            batch: crate::publish::rows_to_batch(&crate::schema::FACT_LABEL, &rows)?,
        });
    }
    update.durable_revision = revision as u64;
    Ok(())
}

#[derive(Debug)]
pub struct Body {
    pub field: &'static str,
    pub text: String,
    pub truncated: bool,
}

/// Read only the declared body fields, truncating inside SQLite before allocation.
/// The caller must first admit exactly one origin namespace and enforce its
/// whole-request deadline. Missing files/rows are ordinary not-found results.
pub fn bodies(state: &Path, uid: &str, deadline: std::time::Instant) -> Result<Vec<Body>> {
    let Some((name, id)) = uid.split_once('/') else {
        return Ok(Vec::new());
    };
    let Some(table) = TABLES.iter().find(|table| {
        table.name == name && matches!(name, "label" | "adjudication" | "lane" | "intervention")
    }) else {
        return Ok(Vec::new());
    };
    let path = state.join(FILE_NAME);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let connection = read_connection(&path)?;
    connection.busy_timeout(std::time::Duration::ZERO)?;
    connection.progress_handler(1000, Some(move || std::time::Instant::now() >= deadline))?;
    connection.execute_batch("BEGIN")?;
    let mut bodies = Vec::new();
    for column in table
        .columns
        .iter()
        .filter(|column| column.class == Class::Body)
    {
        let body = connection.query_row(&format!("SELECT substr(\"{}\",1,65536),length(\"{}\")>65536 FROM \"{}\" WHERE id=?1 AND \"{}\" IS NOT NULL",column.name,column.name,table.name,column.name),[id],|row| Ok(Body {field:column.name,text:row.get(0)?,truncated:row.get(1)?})).optional()?;
        if let Some(body) = body {
            bodies.push(body);
        }
    }
    Ok(bodies)
}

/// SQLite online backup includes committed WAL records and never overwrites an
/// existing destination. The original store is opened read-only.
pub fn backup(state: &Path, destination: &Path) -> Result<()> {
    let source = read_connection(&state.join(FILE_NAME))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(destination)?;
    let mut target = Connection::open_with_flags(
        destination,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    {
        let backup = rusqlite::backup::Backup::new(&source, &mut target)?;
        backup.run_to_completion(128, std::time::Duration::from_millis(10), None)?;
    }
    drop(target);
    file.sync_all()?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Resolve from the analytics directory without putting durable custody under
/// analytics-store (which explicit analytics reset is permitted to remove).
pub(crate) fn path_for_analytics(analytics: &Path) -> Result<PathBuf> {
    Ok(analytics
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| Error::invalid("analytics store has no state directory"))?
        .join(FILE_NAME))
}

#[cfg(test)]
mod tests;
