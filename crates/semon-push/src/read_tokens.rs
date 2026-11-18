//! Receiver-owner credentials for reading received history.
use crate::{
    credentials::Secret,
    enrollment::{Error, Registry, Store, random_id},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

type Result<T> = std::result::Result<T, Error>;
const PREFIX: &str = "read_";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    tokens: Vec<Token>,
    audit: Vec<Audit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    id: String,
    sha256: [u8; 32],
    created_at: u64,
    revoked_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Audit {
    id: String,
    time: u64,
    action: Action,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Created,
    Revoked,
}

pub struct Status {
    pub id: String,
    pub revoked: bool,
}

pub fn create(dir: &Path, now: u64) -> Result<(String, Secret)> {
    let id = random_id()?;
    let secret = Secret::new(format!("{PREFIX}{}", random_id()?));
    Store::open(dir)?.pairing_transaction(0, |registry| {
        let time = now.max(registry.latest);
        registry.latest = time;
        registry.read_tokens.tokens.push(Token {
            id: id.clone(),
            sha256: secret.hash(),
            created_at: time,
            revoked_at: None,
        });
        registry.read_tokens.audit.push(Audit {
            id: id.clone(),
            time,
            action: Action::Created,
        });
        Ok((id, secret))
    })
}

pub fn list(dir: &Path) -> Result<Vec<Status>> {
    Ok(Store::open(dir)?
        .snapshot()?
        .read_tokens
        .tokens
        .into_iter()
        .map(|token| Status {
            id: token.id,
            revoked: token.revoked_at.is_some(),
        })
        .collect())
}

pub fn revoke(dir: &Path, id: &str, now: u64) -> Result<()> {
    Store::open(dir)?.pairing_transaction(0, |registry| {
        let token = registry
            .read_tokens
            .tokens
            .iter_mut()
            .find(|token| token.id == id && token.revoked_at.is_none())
            .ok_or(Error::Invalid)?;
        let time = now.max(registry.latest);
        registry.latest = time;
        token.revoked_at = Some(time);
        registry.read_tokens.audit.push(Audit {
            id: id.to_owned(),
            time,
            action: Action::Revoked,
        });
        Ok(())
    })
}

pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Registry {
    pub(crate) fn read_token_id(&self, secret: &str) -> Option<&str> {
        use sha2::{Digest, Sha256};
        if !valid_id(secret.strip_prefix(PREFIX)?) {
            return None;
        }
        let hash = Sha256::digest(secret.as_bytes()).into();
        self.read_tokens.tokens.iter().find_map(|token| {
            (token.revoked_at.is_none() && crate::simple_pair::constant_eq(&hash, &token.sha256))
                .then_some(token.id.as_str())
        })
    }

    pub(crate) fn read_token_active(&self, id: &str) -> bool {
        self.read_tokens
            .tokens
            .iter()
            .any(|token| token.id == id && token.revoked_at.is_none())
    }
}

impl State {
    pub(crate) fn len(&self) -> usize {
        self.tokens.len()
    }

    pub(crate) fn terminal_reserve(&self) -> u64 {
        // Space for each active token's revocation timestamp and audit entry.
        self.tokens
            .iter()
            .filter(|token| token.revoked_at.is_none())
            .count() as u64
            * 160
    }

    pub(crate) fn validate(&self, latest: u64) -> Result<()> {
        let mut ids = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        let mut events = BTreeSet::new();
        for token in &self.tokens {
            if !valid_id(&token.id)
                || !ids.insert(&token.id)
                || !hashes.insert(token.sha256)
                || token.created_at > latest
            {
                return Err(Error::Invalid);
            }
            events.insert((&token.id, token.created_at, false));
            if let Some(time) = token.revoked_at {
                if time < token.created_at || time > latest {
                    return Err(Error::Invalid);
                }
                events.insert((&token.id, time, true));
            }
        }
        for event in &self.audit {
            if !events.remove(&(&event.id, event.time, event.action == Action::Revoked)) {
                return Err(Error::Invalid);
            }
        }
        if !events.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub(crate) fn follows(&self, old: &Self) -> Result<()> {
        if !self.audit.starts_with(&old.audit) || self.tokens.len() < old.tokens.len() {
            return Err(Error::Terminal);
        }
        for (prior, next) in old.tokens.iter().zip(&self.tokens) {
            if prior.id != next.id
                || prior.sha256 != next.sha256
                || prior.created_at != next.created_at
                || (prior.revoked_at.is_some() && prior.revoked_at != next.revoked_at)
            {
                return Err(Error::Terminal);
            }
        }
        Ok(())
    }
}
