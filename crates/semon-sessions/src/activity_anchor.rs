//! Exact, on-demand activity-to-transcript joins inside the caller's snapshot.
use crate::{
    events::session_activity::{ActivityStepId, Usage},
    model::summary::CatalogRow,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

/// Resolve one activity step without reading native bodies. Hosts authorize
/// the selected machine/session before and after this request.
pub fn session_activity_anchor(
    options: &crate::Options,
    source_key: &str,
    query: &str,
) -> crate::ViewerReply {
    session_activity_anchor_with_gate(options, source_key, query, || Ok(()))
}

pub(crate) fn session_activity_anchor_with_gate(
    options: &crate::Options,
    source_key: &str,
    query: &str,
    before_read: impl FnOnce() -> Result<(), crate::ViewerReply>,
) -> crate::ViewerReply {
    use crate::viewer::{decoded, query_value};
    let reply = |body: Value| crate::ViewerReply {
        status: 200,
        content_type: "application/json; charset=utf-8",
        body: body.to_string().into_bytes(),
        etag: None,
    };
    let read = || -> Result<crate::ViewerReply, Box<dyn std::error::Error>> {
        let argument = |name| query_value(query, name).and_then(decoded);
        for name in ["sid", "generation", "ordinal", "id", "scope", "machine"] {
            if query
                .split('&')
                .filter(|part| part.split('=').next() == Some(name))
                .count()
                > 1
            {
                return Ok(crate::catalog::error(
                    400,
                    "invalid_arguments",
                    "Duplicate anchor argument.",
                    false,
                ));
            }
        }
        let (Some(key), Some(generation), Some(ordinal), Some(id)) = (
            argument("sid"),
            argument("generation"),
            argument("ordinal").and_then(|v| v.parse::<u64>().ok()),
            argument("id").and_then(|v| serde_json::from_str::<Value>(&v).ok()),
        ) else {
            return Ok(crate::catalog::error(
                400,
                "invalid_arguments",
                "Supply sid, generation, ordinal and a JSON step id.",
                false,
            ));
        };
        let step = json!({"generation":generation,"ordinal":ordinal,"id":id});
        if key.is_empty()
            || key.len() > 4096
            || crate::query::validate_query_call("read_transcript", &json!({"id":key,"step":step}))
                .is_err()
            || argument("scope").is_some_and(|s| s != "retained_history")
        {
            return Ok(crate::catalog::error(
                400,
                "invalid_arguments",
                "Invalid activity anchor.",
                false,
            ));
        }
        if let Err(reply) = before_read() {
            return Ok(reply);
        }
        let store = crate::storage::runtime::RuntimeStore::for_source(options, source_key);
        if store.is_postgres() {
            return Ok(reply(unavailable("unsupported_storage")));
        }
        let mut db = store.selected_connection(source_key)?;
        let tx = db.transaction()?;
        let Some((identity, _)) = crate::catalog::catalog_selection_in_snapshot(
            options,
            source_key,
            &key,
            crate::CatalogReadScope::RetainedHistory,
            &tx,
        )?
        else {
            return Ok(reply(unavailable("stale_activity")));
        };
        let marker: Option<String> = tx
            .query_row(
                "SELECT value FROM meta WHERE key='slot_projection_catalog_generation'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if marker.as_deref() != Some(identity.generation.as_str()) {
            return Ok(reply(unavailable("stale_transcript")));
        }
        let history = crate::history_projection::catalog(&tx, &key)?;
        let text: Option<String> = match history.as_ref() {
            Some(text) => Some(text.clone()),
            None => tx
                .query_row(
                    "SELECT CASE WHEN octet_length(metadata)<=1048576 THEN metadata ELSE NULL END FROM session_catalog WHERE session_key=?1",
                    [&key],
                    |r| r.get(0),
                )
                .optional()?,
        };
        let Some(text) = text else {
            return Ok(reply(unavailable("stale_activity")));
        };
        let row: CatalogRow = serde_json::from_str(&text)?;
        let result = resolve(
            &tx,
            &row,
            &step,
            &crate::pricing::snapshot().fingerprint,
            history.is_some(),
        )?;
        Ok(reply(result))
    };
    read().unwrap_or_else(|_| reply(unavailable("stale_transcript")))
}

pub(crate) fn unavailable(reason: &str) -> Value {
    json!({"available": false, "reason": reason})
}

pub(crate) fn resolve(
    db: &Connection,
    row: &CatalogRow,
    step: &Value,
    price: &str,
    history: bool,
) -> rusqlite::Result<Value> {
    let source = crate::retention::source_generation(&row.sources)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let Some(generation) = step["generation"].as_str() else {
        return Ok(unavailable("stale_activity"));
    };
    let Some(ordinal) = step["ordinal"].as_u64().and_then(|n| i64::try_from(n).ok()) else {
        return Ok(unavailable("stale_activity"));
    };
    let header: Option<(String, String, u32, String)> = db.query_row(
        "SELECT generation,source_generation,rules_version,pricing_fingerprint FROM session_activity_projections WHERE session_key=?1",
        [&row.key], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).optional()?;
    let Some((stored, activity_source, rules, fingerprint)) = header else {
        return Ok(unavailable("stale_activity"));
    };
    if stored != generation
        || rules != crate::events::session_activity::ACTIVITY_RULES_VERSION
        || fingerprint != price
    {
        return Ok(unavailable("stale_activity"));
    }
    if activity_source != source {
        return Ok(unavailable("source_generation_mismatch"));
    }
    let saved: Option<String> = db.query_row(
        "SELECT metadata FROM session_activity_steps WHERE session_key=?1 AND generation=?2 AND ordinal=?3 AND pricing_fingerprint=?4 AND octet_length(metadata)<=1048576",
        params![row.key,generation,ordinal,price], |r| r.get(0),
    ).optional()?;
    let Some(saved) = saved else {
        return Ok(unavailable("stale_activity"));
    };
    let saved: Value = serde_json::from_str(&saved).map_err(|_| rusqlite::Error::InvalidQuery)?;
    if saved["step"]["id"] != step["id"] {
        return Ok(unavailable("stale_activity"));
    }
    let id: ActivityStepId = serde_json::from_value(saved["step"]["id"].clone())
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let usage: Usage = serde_json::from_value(saved["usage"].clone())
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let (headers, slots, incomplete) = if history {
        (
            "session_history_projections",
            "session_history_slots",
            "incomplete",
        )
    } else {
        ("session_slot_projections", "session_slots", "0")
    };
    let header: Option<(String, Option<String>, u32, bool, i64)> = db.query_row(
        &format!("SELECT generation,source_generation,version,{incomplete},total FROM {headers} WHERE session_key=?1"),
        [&row.key], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional()?;
    let Some((transcript, transcript_source, version, incomplete, total)) = header else {
        return Ok(unavailable("stale_transcript"));
    };
    if version != crate::slot_projection::VERSION {
        return Ok(unavailable("stale_transcript"));
    }
    if transcript_source.as_deref() != Some(&source) {
        return Ok(unavailable("source_generation_mismatch"));
    }
    if incomplete {
        return Ok(unavailable("history_incomplete"));
    }
    let (count, first, last): (i64, Option<i64>, Option<i64>) = db.query_row(
        &format!("SELECT count(*),min(slot),max(slot) FROM {slots} WHERE session_key=?1"),
        [&row.key],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if count != total || (total > 0 && (first != Some(0) || last != Some(total - 1))) {
        return Ok(unavailable("history_incomplete"));
    }
    // Only assistant-authored entries qualify. A result, marker, user message or
    // internal code-mode call is never a substitute for an exact rendered record.
    let assistant = "json_extract(metadata,'$.recipe.recipe') IN ('A','Think','Tool','Operation','Yielded','Sent','H')";
    let found: Option<(i64, &str)> = match (&id, usage) {
        (ActivityStepId::Claude(_), Usage::Claude(usage)) => {
            let ids: Vec<_> = usage.record_ids.iter().take(256).collect();
            let ids = serde_json::to_string(&ids).map_err(|_| rusqlite::Error::InvalidQuery)?;
            let slot: Option<i64> = db.query_row(&format!("SELECT slot FROM {slots} WHERE session_key=?1 AND {assistant} AND json_extract(metadata,'$.native_event_id') IN (SELECT value FROM json_each(?2)) ORDER BY slot LIMIT 1"), params![row.key,ids], |r|r.get(0)).optional()?;
            if let Some(slot) = slot {
                Some((slot, "message_record_id"))
            } else {
                let path = saved["step"]["position"]["source"]
                    .as_str()
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                let offset =
                    i64::try_from(usage.offset).map_err(|_| rusqlite::Error::InvalidQuery)?;
                db.query_row(&format!("SELECT slot FROM {slots} WHERE session_key=?1 AND {assistant} AND json_extract(metadata,'$.file.path')=?2 AND json_extract(metadata,'$.offset')=?3 AND ?4<=256 ORDER BY slot LIMIT 1"),params![row.key,path,offset,usage.record_ids.len() as i64],|r|r.get(0)).optional()?.map(|slot|(slot,"usage_record"))
            }
        }
        (ActivityStepId::Codex(_), Usage::Codex(_)) => {
            if !crate::events::EventCache::selected_roles_current(db, &row.sources)? {
                return Ok(unavailable("source_generation_mismatch"));
            }
            let identity = serde_json::to_string(&id).map_err(|_| rusqlite::Error::InvalidQuery)?;
            // The parser records the full tuple only on exact native calls. A
            // rendered operation points back to its code-mode parent's offset.
            db.query_row(&format!("SELECT s.slot FROM {slots} s JOIN files f ON f.path=json_extract(s.metadata,'$.file.path') JOIN events e ON e.file_id=f.file_id AND e.extra=0 AND e.k='tool' AND e.parent IS NULL AND e.o=CASE WHEN json_extract(s.metadata,'$.recipe.recipe')='Operation' THEN json_extract(s.metadata,'$.recipe.script_offset') ELSE json_extract(s.metadata,'$.offset') END WHERE s.session_key=?1 AND json_extract(s.metadata,'$.recipe.recipe') IN ('Tool','Operation','Yielded','Sent','H') AND json_extract(e.y,'$.activity_observation.step_id')=json(?2) AND NOT EXISTS(SELECT 1 FROM events earlier WHERE earlier.file_id=e.file_id AND earlier.extra=0 AND earlier.k='tool' AND earlier.parent IS NULL AND earlier.o<e.o AND json_extract(earlier.y,'$.activity_observation.step_id')=json(?2)) ORDER BY s.slot LIMIT 1"), params![row.key,identity], |r|r.get(0)).optional()?.map(|slot|(slot,"tool_call"))
        }
        _ => None,
    };
    Ok(match found {
        Some((slot, basis)) => {
            json!({"available":true,"activity_generation":generation,"step":{"ordinal":ordinal,"id":id},"source_generation":source,"transcript_generation":crate::transcript_range::entry_generation(&transcript),"slot":slot,"basis":basis})
        }
        None => unavailable("no_exact_record"),
    })
}
