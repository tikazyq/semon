//! Activity-to-transcript addresses from one selected SQLite snapshot.
use crate::{
    events::{session_activity::ActivityStepId, store::session_activity},
    slot_projection::VERSION,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Step {
    pub(crate) generation: String,
    pub(crate) ordinal: i64,
    pub(crate) id: ActivityStepId,
}

impl Step {
    pub(crate) fn parse(value: Value) -> Option<Self> {
        let step: Self = serde_json::from_value(value).ok()?;
        let valid = match &step.id {
            ActivityStepId::Claude(id) => !id.is_empty(),
            ActivityStepId::Codex(ids) => ids.iter().all(|id| !id.is_empty()),
        };
        (valid && (1..=128).contains(&step.generation.len()) && step.ordinal >= 0).then_some(step)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    StaleActivity,
    StaleTranscript,
    SourceGenerationMismatch,
    HistoryIncomplete,
    NoExactRecord,
    UnsupportedStorage,
}

impl Refusal {
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::StaleActivity => "stale_activity",
            Self::StaleTranscript => "stale_transcript",
            Self::SourceGenerationMismatch => "source_generation_mismatch",
            Self::HistoryIncomplete => "history_incomplete",
            Self::NoExactRecord => "no_exact_record",
            Self::UnsupportedStorage => "unsupported_storage",
        }
    }

    pub(crate) fn body(&self) -> Value {
        json!({"available": false, "reason": self.reason()})
    }
}

#[derive(Debug)]
pub(crate) struct Anchor {
    pub(crate) slot: usize,
    pub(crate) transcript_generation: String,
    basis: &'static str,
}

impl Anchor {
    pub(crate) fn body(&self, step: &Step, source_generation: &str) -> Value {
        json!({
            "available": true,
            "activity_generation": step.generation,
            "step": {"ordinal": step.ordinal, "id": step.id},
            "source_generation": source_generation,
            "transcript_generation": crate::transcript_range::entry_generation(&self.transcript_generation),
            "slot": self.slot,
            "basis": self.basis,
        })
    }
}

pub(crate) fn resolve(
    tx: &Transaction<'_>,
    key: &str,
    source_generation: &str,
    history: bool,
    step: &Step,
    price: &str,
) -> rusqlite::Result<Result<Anchor, Refusal>> {
    let (position, usage) =
        match session_activity::anchor_evidence(tx, key, source_generation, step, price)? {
            Ok(evidence) => evidence,
            Err(reason) => return Ok(Err(reason)),
        };
    let (headers, table, incomplete) = if history {
        (
            "session_history_projections",
            "session_history_slots",
            "incomplete",
        )
    } else {
        ("session_slot_projections", "session_slots", "0")
    };
    type Header = (String, u32, Option<String>, i64, bool);
    let header: Option<Header> = tx.query_row(
        &format!("SELECT generation,version,source_generation,total,{incomplete} FROM {headers} WHERE session_key=?1"),
        [key], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).optional()?;
    let Some((transcript_generation, VERSION, sources, total, incomplete)) = header else {
        return Ok(Err(Refusal::StaleTranscript));
    };
    if sources.as_deref() != Some(source_generation) {
        return Ok(Err(Refusal::SourceGenerationMismatch));
    }
    if incomplete {
        return Ok(Err(Refusal::HistoryIncomplete));
    }
    // Slots carry only exact native evidence. Prefer a matching Claude UUID
    // over the usage position even if the usage position sorts first.
    use crate::events::session_activity::Usage;
    let matched: Option<(i64, &str)> = match (&step.id, usage) {
        (ActivityStepId::Claude(_), Usage::Claude(usage)) if usage.record_ids.len() <= 256 => {
            let ids = encode(&usage.record_ids)?;
            let slot: Option<i64> = tx.query_row(
                &format!("SELECT slot FROM {table} WHERE session_key=?1 AND slot>=0 AND slot<?2
                    AND json_valid(metadata) AND json_extract(metadata,'$.activity_record.Claude') IN (SELECT value FROM json_each(?3))
                    ORDER BY slot LIMIT 1"), params![key, total, ids], |row| row.get(0),
            ).optional()?;
            if let Some(slot) = slot {
                Some((slot, "claude_record_id"))
            } else if let Ok(offset) = i64::try_from(position.offset) {
                tx.query_row(
                    &format!("SELECT slot FROM {table} WHERE session_key=?1 AND slot>=0 AND slot<?2
                        AND json_valid(metadata) AND json_type(metadata,'$.activity_record.Claude') IS NOT NULL
                        AND json_extract(metadata,'$.file.path')=?3 AND json_extract(metadata,'$.offset')=?4
                        ORDER BY slot LIMIT 1"),
                    params![key, total, position.source, offset],
                    |row| Ok((row.get(0)?, "claude_usage_record")),
                ).optional()?
            } else {
                None
            }
        }
        (ActivityStepId::Codex(identity), Usage::Codex(_)) => tx.query_row(
            &format!("SELECT slot FROM {table} WHERE session_key=?1 AND slot>=0 AND slot<?2
                AND json_valid(metadata) AND json_extract(metadata,'$.activity_record.Codex')=json(?3)
                ORDER BY slot LIMIT 1"),
            params![key, total, encode(identity)?], |row| Ok((row.get(0)?, "codex_tool_call")),
        ).optional()?,
        _ => None,
    };
    let Some((slot, basis)) = matched else {
        return Ok(Err(Refusal::NoExactRecord));
    };
    let slot = usize::try_from(slot).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(Ok(Anchor {
        slot,
        transcript_generation,
        basis,
    }))
}

pub(crate) fn viewer_reply(
    storage: &crate::storage::runtime::RuntimeStore,
    options: &crate::Options,
    source_key: &str,
    query: &str,
    before_read: impl FnOnce() -> Result<(), crate::ViewerReply>,
) -> crate::ViewerReply {
    use crate::{
        CatalogReadScope, catalog,
        viewer::{decoded, query_value},
    };
    let arg = |name| query_value(query, name).and_then(decoded);
    let invalid = || {
        catalog::error(
            400,
            "invalid_arguments",
            "Supply one session key, activity generation, ordinal and JSON step id.",
            false,
        )
    };
    let Some(key) = arg("sid").filter(|key| (1..=4096).contains(&key.len())) else {
        return invalid();
    };
    let Some(step) = (|| {
        Step::parse(json!({
            "generation": arg("generation")?,
            "ordinal": arg("ordinal")?.parse::<i64>().ok()?,
            "id": serde_json::from_str::<Value>(&arg("id")?).ok()?,
        }))
    })() else {
        return invalid();
    };
    if arg("scope").is_some_and(|scope| scope != "retained_history")
        || ["sid", "generation", "ordinal", "id", "scope", "machine"]
            .iter()
            .any(|name| {
                query
                    .split('&')
                    .filter(|part| part.split('=').next() == Some(*name))
                    .count()
                    > 1
            })
    {
        return invalid();
    }
    if storage.is_postgres() {
        return response(Refusal::UnsupportedStorage.body());
    }
    if let Err(reply) = before_read() {
        return reply;
    }
    let read = || -> Result<crate::ViewerReply, Box<dyn std::error::Error>> {
        let mut db = storage.selected_connection(source_key)?;
        let tx = db.transaction()?;
        let identity = match catalog::catalog_selection_in_snapshot(
            options,
            source_key,
            &key,
            CatalogReadScope::RetainedHistory,
            &tx,
        ) {
            Ok(Some((identity, _))) => identity,
            Ok(None) => return Ok(response(Refusal::StaleActivity.body())),
            Err(_) => return Ok(response(Refusal::StaleTranscript.body())),
        };
        let generation: Option<String> = tx
            .query_row(
                "SELECT value FROM meta WHERE key='slot_projection_catalog_generation'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if generation.as_deref() != Some(identity.generation.as_str()) {
            return Ok(response(Refusal::StaleTranscript.body()));
        }
        let history = crate::history_projection::catalog(&tx, &key)?;
        let text = if let Some(text) = &history {
            text.clone()
        } else {
            tx.query_row(
                "SELECT metadata FROM session_catalog WHERE session_key=?1",
                [&key],
                |row| row.get(0),
            )?
        };
        let row: crate::model::summary::CatalogRow = serde_json::from_str(&text)?;
        let sources = crate::retention::source_generation(&row.sources)?;
        let price = crate::pricing::snapshot();
        let result = resolve(
            &tx,
            &key,
            &sources,
            history.is_some(),
            &step,
            &price.fingerprint,
        )?;
        Ok(response(match result {
            Ok(anchor) => anchor.body(&step, &sources),
            Err(reason) => reason.body(),
        }))
    };
    read().unwrap_or_else(|_| response(Refusal::StaleTranscript.body()))
}

fn response(body: Value) -> crate::ViewerReply {
    crate::transcript_range::reply(200, body)
}

fn encode(value: &impl serde::Serialize) -> rusqlite::Result<String> {
    serde_json::to_string(value)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
}
