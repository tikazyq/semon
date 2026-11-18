//! One-time pairing and revocable push authority, committed in the receiver registry.
use crate::{
    credentials::Secret,
    enrollment::{Error, Registry, Store},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const MAX_BODY: usize = 4096;
pub const CODE_LIFETIME: u64 = 600;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub pending: Option<Pending>,
    pub failures: u32,
    pub pause_until: u64,
    pub bearers: Vec<PushBearer>,
    pub audit: Vec<Audit>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub sha256: [u8; 32],
    pub expires_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushBearer {
    pub id: String,
    pub machine: String,
    pub sha256: [u8; 32],
    pub revoked_at: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    pub time: u64,
    pub action: String,
    pub machine: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub code: String,
    pub machine: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub machine: String,
    pub bearer: String,
}

pub fn now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|e| e.to_string())
}
pub fn initialize(dir: &Path) -> Result<(), String> {
    crate::tokens::prepare_private_dir(dir, true)?;
    crate::enrollment::refuse_legacy_tokens(dir).map_err(|e| e.to_string())?;
    if !dir.join(crate::enrollment::DIRECTORY).exists() {
        Store::initialize(dir).map_err(|e| e.to_string())?;
    }
    Registry::read_current(dir).map_err(|e| e.to_string())?;
    Ok(())
}
pub fn issue(dir: &Path, now: u64) -> Result<Secret, Error> {
    let mut store = Store::open(dir)?;
    let mut next = store.snapshot()?;
    let now = now.max(next.latest);
    if now < next.push_pair.pause_until {
        return Err(Error::GateUnavailable);
    }
    let code = Secret::new(crate::enrollment::random_id()?[..16].to_owned());
    next.latest = now;
    next.push_pair.pending = Some(Pending {
        sha256: code.hash(),
        expires_at: now.saturating_add(CODE_LIFETIME),
    });
    next.push_pair.audit.push(Audit {
        time: now,
        action: "code_issued".into(),
        machine: None,
    });
    next.check_admission()?;
    store.commit(next.revision(), &next)?;
    Ok(code)
}
pub fn redeem(dir: &Path, bytes: &[u8], now: u64) -> Result<Response, Error> {
    if bytes.len() > MAX_BODY {
        return Err(Error::Invalid);
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    if !semon_sessions::machine_id::valid(&request.machine) || request.code.len() > 128 {
        return Err(Error::Invalid);
    }
    let mut store = Store::open(dir)?;
    let mut next = store.snapshot()?;
    let now = now.max(next.latest);
    if now < next.push_pair.pause_until {
        return Err(Error::GateUnavailable);
    }
    let pending = next.push_pair.pending.take();
    let had_pending = pending.is_some();
    let accepted = pending.is_some_and(|p| {
        now < p.expires_at
            && crate::credentials::ct_eq(&p.sha256, &Secret::new(request.code).hash())
    });
    next.latest = now;
    if !accepted {
        next.push_pair.failures = next.push_pair.failures.saturating_add(1);
        next.push_pair.pause_until = now.saturating_add(if next.push_pair.failures >= 3 {
            300
        } else {
            30
        });
        if had_pending {
            next.push_pair.audit.push(Audit {
                time: now,
                action: "code_burned".into(),
                machine: None,
            });
        }
        store.commit(next.revision(), &next)?;
        return Err(Error::GateUnavailable);
    }
    let secret = Secret::generate()?;
    revoke_tokens(&mut next, &request.machine, now);
    if !next.machines.iter().any(|m| m.id == request.machine) {
        next.machines
            .push(semon_sessions::received_registry::ReceivedMachine {
                id: request.machine.clone(),
                directory: request.machine.clone(),
                owner_name: None,
            });
    }
    next.push_pair.bearers.push(PushBearer {
        id: crate::enrollment::random_id()?,
        machine: request.machine.clone(),
        sha256: secret.hash(),
        revoked_at: None,
    });
    next.push_pair.audit.push(Audit {
        time: now,
        action: "paired".into(),
        machine: Some(request.machine.clone()),
    });
    next.check_admission()?;
    store.commit(next.revision(), &next)?;
    Ok(Response {
        machine: request.machine,
        bearer: secret.expose().to_owned(),
    })
}
fn revoke_tokens(registry: &mut Registry, machine: &str, now: u64) {
    let ids: Vec<_> = registry
        .enrollments
        .iter()
        .filter(|e| e.machine == machine && e.revoked_at.is_none())
        .map(|e| e.enrollment_id.clone())
        .collect();
    for id in ids {
        registry.revoke_enrollment(&id, Some(crate::credentials::Kind::MirrorPush), now);
    }
    for token in &mut registry.push_pair.bearers {
        if token.machine == machine && token.revoked_at.is_none() {
            token.revoked_at = Some(now);
        }
    }
}
pub fn revoke(dir: &Path, machine: &str, now: u64) -> Result<(), Error> {
    let mut store = Store::open(dir)?;
    let mut next = store.snapshot()?;
    if !next.machines.iter().any(|m| m.id == machine) {
        return Err(Error::Invalid);
    }
    let now = now.max(next.latest);
    next.latest = now;
    revoke_tokens(&mut next, machine, now);
    next.push_pair.audit.push(Audit {
        time: now,
        action: "revoked".into(),
        machine: Some(machine.into()),
    });
    store.commit(next.revision(), &next)
}
impl State {
    pub(crate) fn validate(&self, registry: &Registry) -> bool {
        let mut ids = std::collections::BTreeSet::new();
        let mut machines = std::collections::BTreeSet::new();
        let mut hashes = std::collections::BTreeSet::new();
        self.bearers.iter().all(|b| {
            crate::enrollment::opaque(&b.id)
                && ids.insert(&b.id)
                && hashes.insert(b.sha256)
                && !registry
                    .credentials
                    .iter()
                    .any(|c| c.credential_id == b.id || c.sha256 == b.sha256)
                && !registry.enrollments.iter().any(|e| e.enrollment_id == b.id)
                && b.revoked_at.is_none_or(|time| time <= registry.latest)
                && registry.machines.iter().any(|m| m.id == b.machine)
                && (b.revoked_at.is_some() || machines.insert(&b.machine))
        }) && self.audit.iter().all(|a| {
            a.time <= registry.latest
                && matches!(
                    a.action.as_str(),
                    "code_issued" | "code_burned" | "paired" | "revoked"
                )
                && a.machine
                    .as_ref()
                    .is_none_or(|m| registry.machines.iter().any(|r| &r.id == m))
        })
    }
    pub(crate) fn follows(&self, old: &Self) -> bool {
        self.audit.starts_with(&old.audit)
            && self.failures >= old.failures
            && self.pause_until >= old.pause_until
            && old.bearers.iter().all(|b| {
                self.bearers.iter().any(|n| {
                    n.id == b.id
                        && n.machine == b.machine
                        && n.sha256 == b.sha256
                        && (b.revoked_at.is_none() || n.revoked_at == b.revoked_at)
                })
            })
    }
}
