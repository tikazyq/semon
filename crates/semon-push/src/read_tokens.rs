//! Owner read credentials. Push and pairing authority never consult this table.
#[cfg(test)]
#[path = "read_tokens_tests.rs"]
mod tests;
use crate::{
    credentials::Secret,
    enrollment::{Error, Registry, Store},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadToken {
    pub id: String,
    sha256: [u8; 32],
    pub created_at: u64,
    pub revoked_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Audit {
    time: u64,
    id: String,
    action: Action,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Create,
    Revoke,
}

pub fn create(dir: &Path, now: u64) -> Result<(String, Secret)> {
    let mut store = Store::open(dir)?;
    store.pairing_transaction(0, |r| {
        let now = now.max(r.latest);
        let id = crate::enrollment::random_id()?;
        let secret = Secret::generate()?;
        r.read_tokens.push(ReadToken {
            id: id.clone(),
            sha256: secret.hash(),
            created_at: now,
            revoked_at: None,
        });
        r.read_token_audit.push(Audit {
            time: now,
            id: id.clone(),
            action: Action::Create,
        });
        r.latest = now;
        r.check_admission()?;
        Ok((id, secret))
    })
}

/// Listing takes the same registry transaction lock as issuance and revocation.
pub fn list(dir: &Path) -> Result<Vec<ReadToken>> {
    Ok(Store::open(dir)?.snapshot()?.read_tokens)
}

pub fn revoke(dir: &Path, id: &str, now: u64) -> Result<()> {
    let mut store = Store::open(dir)?;
    store.pairing_transaction(0, |r| {
        let now = now.max(r.latest);
        let token = r
            .read_tokens
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or(Error::Invalid)?;
        if token.revoked_at.is_none() {
            token.revoked_at = Some(now);
            r.read_token_audit.push(Audit {
                time: now,
                id: id.into(),
                action: Action::Revoke,
            });
        }
        r.latest = now;
        Ok(())
    })
}

impl Registry {
    pub(crate) fn read_token(&self, raw: &str) -> Option<&ReadToken> {
        if raw.is_empty() || raw.len() > 512 {
            return None;
        }
        let hash = Secret::new(raw.into()).hash();
        self.read_tokens.iter().find(|t| {
            let difference = t
                .sha256
                .iter()
                .zip(hash)
                .fold(0u8, |acc, (a, b)| acc | (a ^ b));
            std::hint::black_box(difference) == 0 && t.revoked_at.is_none()
        })
    }

    pub(crate) fn validate_read_tokens(&self) -> Result<()> {
        let mut ids = std::collections::BTreeSet::new();
        let mut hashes = std::collections::BTreeSet::new();
        for token in &self.read_tokens {
            if token.id.len() != 64
                || !token
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || !ids.insert(&token.id)
                || !hashes.insert(token.sha256)
                || token.created_at > self.latest
                || token
                    .revoked_at
                    .is_some_and(|t| t < token.created_at || t > self.latest)
                || self
                    .read_token_audit
                    .iter()
                    .filter(|a| {
                        a.id == token.id && a.action == Action::Create && a.time == token.created_at
                    })
                    .count()
                    != 1
                || self
                    .read_token_audit
                    .iter()
                    .filter(|a| a.id == token.id && a.action == Action::Revoke)
                    .count()
                    != usize::from(token.revoked_at.is_some())
                || token.revoked_at.is_some_and(|time| {
                    !self
                        .read_token_audit
                        .iter()
                        .any(|a| a.id == token.id && a.action == Action::Revoke && a.time == time)
                })
            {
                return Err(Error::Invalid);
            }
        }
        if self
            .read_token_audit
            .iter()
            .any(|a| a.time > self.latest || !ids.contains(&a.id))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub(crate) fn read_tokens_follow(&self, old: &Self) -> Result<()> {
        if !self.read_token_audit.starts_with(&old.read_token_audit) {
            return Err(Error::Terminal);
        }
        for previous in &old.read_tokens {
            let next = self
                .read_tokens
                .iter()
                .find(|t| t.id == previous.id)
                .ok_or(Error::Terminal)?;
            let mut expected = previous.clone();
            expected.revoked_at = next.revoked_at;
            if &expected != next
                || previous
                    .revoked_at
                    .is_some_and(|t| Some(t) != next.revoked_at)
            {
                return Err(Error::Terminal);
            }
        }
        Ok(())
    }
}
