//! Origin-local text, projected only from the verified ingest batch.

use rusqlite::{OptionalExtension, Transaction, params};
use semon_asi::input::encode_component;
use serde_json::Value;

use super::super::{FileIndex, field, record_time};

pub(super) const SCHEMA: &str = r#"
CREATE TABLE body_state (
    file_id INTEGER PRIMARY KEY,
    turn TEXT NOT NULL,
    step TEXT,
    next_ord INTEGER NOT NULL,
    response_from INTEGER NOT NULL
) STRICT;
CREATE TABLE body (
    id INTEGER PRIMARY KEY,
    file_id INTEGER NOT NULL,
    body_uid TEXT NOT NULL,
    session_uid TEXT NOT NULL,
    turn_uid TEXT NOT NULL,
    step_uid TEXT,
    part TEXT NOT NULL,
    ord INTEGER NOT NULL,
    ts INTEGER,
    text TEXT NOT NULL
) STRICT;
CREATE INDEX body_file ON body(file_id,ord);
CREATE INDEX body_uid_idx ON body(body_uid);
CREATE INDEX body_step ON body(step_uid,ord);
CREATE INDEX body_turn ON body(turn_uid,ord);
CREATE VIRTUAL TABLE body_fts USING fts5(text, content='body', content_rowid='id', tokenize='unicode61 remove_diacritics 2');
CREATE TRIGGER body_insert AFTER INSERT ON body BEGIN
    INSERT INTO body_fts(rowid,text) VALUES(new.id,new.text);
END;
CREATE TRIGGER body_delete AFTER DELETE ON body BEGIN
    INSERT INTO body_fts(body_fts,rowid,text) VALUES('delete',old.id,old.text);
END;
"#;

#[derive(Clone, Debug, Default)]
pub(crate) struct Batch {
    harness: String,
    records: Vec<Record>,
    lines: i64,
}

#[derive(Clone, Debug)]
struct Record {
    // A physical record ordinal is independent of the path and byte lengths.
    ord: i64,
    ts: Option<i64>,
    turn: Option<String>,
    step: Option<String>,
    parts: Vec<(&'static str, String)>,
    response: Option<String>,
}

impl Batch {
    pub(crate) fn new(harness: &str) -> Self {
        Self {
            harness: harness.into(),
            ..Self::default()
        }
    }

    pub(crate) fn observe(&mut self, record: Option<&Value>) {
        let ord = self.lines;
        self.lines += 1;
        let Some(record) = record else { return };
        let mut entry = Record {
            ord,
            ts: record_time(record),
            turn: None,
            step: None,
            parts: Vec::new(),
            response: None,
        };
        match self.harness.as_str() {
            "claude" => entry.claude(record),
            "codex" => entry.codex(record),
            "copilot" => entry.copilot(record),
            _ => return,
        }
        if entry.turn.is_some()
            || entry.step.is_some()
            || entry.response.is_some()
            || !entry.parts.is_empty()
        {
            self.records.push(entry);
        }
    }
}

impl Record {
    fn push(&mut self, part: &'static str, text: Option<&str>) {
        if let Some(text) = text.filter(|text| !text.trim().is_empty()) {
            self.parts.push((part, text.to_owned()));
        }
    }

    fn content(&mut self, part: &'static str, content: &Value) {
        self.push(part, content.as_str());
        for block in content.as_array().into_iter().flatten() {
            self.push(part, field(block, "text"));
        }
    }

    fn claude(&mut self, record: &Value) {
        let message = &record["message"];
        let content = &message["content"];
        match field(record, "type") {
            Some("user") => {
                self.content("user", content);
                if !self.parts.is_empty() {
                    self.turn = Some(field(record, "uuid").unwrap_or_default().to_owned());
                }
                for block in content.as_array().into_iter().flatten() {
                    if field(block, "type") == Some("tool_result") {
                        let part = if block["is_error"].as_bool() == Some(true) {
                            "error"
                        } else {
                            "tool_output"
                        };
                        self.content(part, &block["content"]);
                    }
                }
            }
            Some("assistant") => {
                self.step = field(message, "id")
                    .filter(|id| !id.is_empty())
                    .map(|id| format!("claude/{}", encode_component(id)));
                self.content("assistant", content);
                for block in content.as_array().into_iter().flatten() {
                    if field(block, "type") == Some("tool_use") {
                        self.push("command", field(&block["input"], "command"));
                    }
                }
            }
            Some("system") if field(record, "subtype") == Some("api_error") => {
                self.push(
                    "error",
                    field(record, "message").or_else(|| field(&record["error"], "message")),
                );
            }
            _ => {}
        }
    }

    fn codex(&mut self, record: &Value) {
        let payload = &record["payload"];
        let kind = field(payload, "type");
        match field(record, "type") {
            Some("turn_context") => self.turn = field(payload, "turn_id").map(str::to_owned),
            Some("token_usage_record") => {
                if let Some((identity, _, _)) = super::super::CodexNativeUsage::decode(payload) {
                    let identity: [String; 4] =
                        serde_json::from_str(&identity).expect("decoder emits four IDs");
                    self.turn = Some(identity[2].clone());
                    self.response = Some(crate::origin_projection::step_uid_suffix(
                        &super::super::session_activity::ActivityStepId::Codex(identity),
                    ));
                }
            }
            Some("event_msg") => match kind {
                Some("task_started") => {
                    self.turn = Some(field(payload, "turn_id").unwrap_or_default().to_owned())
                }
                Some("error") => self.push("error", field(payload, "message")),
                Some("exec_command_end") => {
                    let part = if payload["exit_code"].as_i64().is_some_and(|code| code != 0) {
                        "error"
                    } else {
                        "tool_output"
                    };
                    self.push(part, field(payload, "aggregated_output"));
                }
                _ => {}
            },
            Some("response_item") => match kind {
                Some("message") => match field(payload, "role") {
                    Some("user") => {
                        for block in payload["content"].as_array().into_iter().flatten() {
                            let text = field(block, "text")
                                .filter(|text| super::super::harness_tag(text).is_none());
                            self.push("user", text);
                        }
                    }
                    Some("assistant") => self.content("assistant", &payload["content"]),
                    _ => {}
                },
                Some("function_call") => {
                    if let Some(arguments) = field(payload, "arguments")
                        .and_then(|text| serde_json::from_str::<Value>(text).ok())
                    {
                        self.push(
                            "command",
                            field(&arguments, "cmd").or_else(|| field(&arguments, "command")),
                        );
                    }
                }
                Some("custom_tool_call") if field(payload, "name") == Some("exec") => {
                    self.push("command", field(payload, "input"))
                }
                Some("function_call_output" | "custom_tool_call_output") => {
                    self.content("tool_output", &payload["output"])
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn copilot(&mut self, record: &Value) {
        let data = &record["data"];
        match field(record, "type") {
            Some("user.message") => {
                self.turn = Some(field(record, "id").unwrap_or_default().to_owned());
                self.push("user", field(data, "content"));
            }
            Some("assistant.message") => {
                self.push("assistant", field(data, "content"));
                for request in data["toolRequests"].as_array().into_iter().flatten() {
                    self.push("command", field(&request["arguments"], "command"));
                }
            }
            Some("tool.execution_complete") => {
                self.push("tool_output", field(&data["result"], "content"));
                self.push("error", field(&data["error"], "message"));
            }
            _ => {}
        }
    }
}

pub(super) fn write(
    tx: &Transaction<'_>,
    file_id: i64,
    path: &str,
    index: &FileIndex,
) -> rusqlite::Result<()> {
    let batch = &index.body_batch;
    if batch.lines == 0 {
        return Ok(());
    }
    let path = std::path::Path::new(path);
    let native = match batch.harness.as_str() {
        "claude" => path
            .file_stem()
            .and_then(|name| name.to_str())
            .map(str::to_owned),
        "codex" => index
            .codex_header
            .as_ref()
            .and_then(|header| header.native_id(path)),
        "copilot" => index.copilot.as_ref().map(|index| index.session_id.clone()),
        _ => None,
    };
    let Some(native) = native.filter(|id| !id.is_empty()) else {
        return Ok(());
    };
    let session = format!("{}/{}", batch.harness, encode_component(&native));
    let (mut turn, mut step, base, mut response_from): (String, Option<String>, i64, i64) = tx
        .query_row(
            "SELECT turn,step,next_ord,response_from FROM body_state WHERE file_id=?1",
            [file_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?
        .unwrap_or_default();
    let mut put = tx.prepare_cached("INSERT INTO body(file_id,body_uid,session_uid,turn_uid,step_uid,part,ord,ts,text) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)")?;
    for record in &batch.records {
        let ord = base + record.ord;
        if let Some(id) = &record.turn {
            if turn != *id || id.is_empty() {
                step = None;
                response_from = ord;
            }
            turn.clone_from(id);
        }
        if let Some(id) = &record.step {
            step = Some(id.clone());
        }
        let fallback = step.as_deref().and_then(|id| id.strip_prefix("claude/"));
        let turn_anchor = if turn.is_empty() {
            fallback
                .map(str::to_owned)
                .unwrap_or_else(|| encode_component(&format!("@{ord}")))
        } else {
            encode_component(&turn)
        };
        let turn_uid = format!("{session}/t/{turn_anchor}");
        if let Some(response) = &record.response {
            let step_uid = format!("{session}/s/{response}");
            // Usage closes the response. Attribute only bodies in this native
            // turn since its previous usage boundary, including prior tail batches.
            tx.execute(
                "UPDATE body SET step_uid=?1,body_uid=?1 || substr(body_uid,length(turn_uid)+1)
                 WHERE file_id=?2 AND turn_uid=?3 AND ord>=?4 AND ord<?5
                   AND part<>'user' AND step_uid IS NULL",
                params![step_uid, file_id, turn_uid, response_from, ord],
            )?;
            response_from = ord + 1;
        }
        for (block, (part, text)) in record.parts.iter().enumerate() {
            let step_uid = (*part != "user")
                .then_some(step.as_deref())
                .flatten()
                .map(|id| format!("{session}/s/{id}"));
            let owner = step_uid.as_deref().unwrap_or(&turn_uid);
            let uid = format!("{owner}/b/{part}/{ord}-{block}");
            put.execute(params![
                file_id, uid, session, turn_uid, step_uid, part, ord, record.ts, text
            ])?;
        }
    }
    tx.execute("INSERT OR REPLACE INTO body_state(file_id,turn,step,next_ord,response_from) VALUES(?1,?2,?3,?4,?5)", params![file_id,turn,step,base + batch.lines,response_from])?;
    Ok(())
}

/// A proven move retains the exact prefix and native session ID. Reindex its
/// bodies under the moved file's ledger in the same transaction.
pub(super) fn relocate(tx: &Transaction<'_>, path: &str) -> rusqlite::Result<()> {
    tx.execute_batch("CREATE TEMP TABLE moved_body AS SELECT * FROM body WHERE 0;")?;
    tx.execute(
        "INSERT INTO moved_body SELECT body.* FROM body JOIN files USING(file_id) WHERE path=?1",
        [path],
    )?;
    tx.execute(
        "DELETE FROM body WHERE file_id=(SELECT file_id FROM files WHERE path=?1)",
        [path],
    )?;
    tx.execute_batch("INSERT INTO body SELECT * FROM moved_body; DROP TABLE moved_body;")
}
