//! One-time pairing for push delivery through a trusted HTTPS reverse proxy.
use crate::{
    Credential, Result, Token,
    body_cache::CacheDirectory,
    credentials::Secret,
    enrollment::{Error, Registry, Store},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::Path,
    time::Duration,
};
use zeroize::Zeroizing;

pub(crate) const ROUTE: &str = "/v1/push/pair";
pub(crate) const CAP: usize = 1024;
const LIFETIME: u64 = 600;
const PAUSE: u64 = 60;
const CONFIG: &str = "pair.json";
const CONFIG_CAP: usize = 4096;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    pending: Option<Pending>,
    pause_until: u64,
    bearers: BTreeMap<String, [u8; 32]>,
    audit: Vec<Audit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    sha256: [u8; 32],
    expires: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Audit {
    time: u64,
    machine: String,
    action: Action,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Pair,
    Replace,
    Revoke,
}

impl State {
    pub(crate) fn valid(&self, registry: &Registry) -> bool {
        let machines: BTreeSet<_> = registry.machines().iter().map(|m| &m.id).collect();
        let mut active = BTreeSet::new();
        let mut time = 0;
        for event in &self.audit {
            if event.time < time
                || event.time > registry.latest
                || !machines.contains(&event.machine)
            {
                return false;
            }
            time = event.time;
            let valid = match event.action {
                Action::Pair => active.insert(&event.machine),
                Action::Replace => active.contains(&event.machine),
                Action::Revoke => active.remove(&event.machine),
            };
            if !valid {
                return false;
            }
        }
        active.into_iter().eq(self.bearers.keys())
            && self.pause_until <= registry.latest.saturating_add(PAUSE)
            && self.pending.as_ref().is_none_or(|pending| {
                pending.expires > self.pause_until
                    && pending.expires <= registry.latest.saturating_add(LIFETIME)
            })
    }

    pub(crate) fn follows(&self, old: &Self) -> bool {
        self.audit.starts_with(&old.audit) && self.pause_until >= old.pause_until
    }

    pub(crate) fn count(&self) -> usize {
        self.bearers.len()
    }

    pub(crate) fn machine(&self, hash: &[u8; 32]) -> Option<String> {
        self.bearers
            .iter()
            .find(|(_, stored)| crate::credentials::ct_eq(stored, hash))
            .map(|(machine, _)| machine.clone())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    machine: String,
    code: String,
}

impl Request {
    pub(crate) fn parse(body: &[u8]) -> Option<Self> {
        if body.len() > CAP {
            return None;
        }
        let request: Self = serde_json::from_slice(body).ok()?;
        semon_sessions::machine_id::valid(&request.machine).then_some(request)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    bearer: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    url: String,
    bearer: String,
}

pub fn issue(dir: &Path) -> Result<Secret> {
    crate::enrollment::refuse_legacy_tokens(dir).map_err(|e| e.to_string())?;
    if !dir
        .join(crate::enrollment::DIRECTORY)
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        crate::tokens::prepare_private_dir(dir, true)?;
        crate::receiver_custody::ReceiverCustody::initialize_for_push(dir)
            .map_err(|e| e.to_string())?;
    }
    issue_at(dir, crate::origin_custody::now()?)
}

fn issue_at(dir: &Path, now: u64) -> Result<Secret> {
    let mut store = Store::open(dir).map_err(|e| e.to_string())?;
    let mut registry = store.snapshot().map_err(|e| e.to_string())?;
    let now = registry.latest.max(now);
    if now < registry.push_pairing.pause_until {
        return Err(format!(
            "pairing is paused for {} seconds",
            registry.push_pairing.pause_until - now
        ));
    }
    let code = Secret::generate().map_err(|e| e.to_string())?;
    registry.latest = now;
    registry.push_pairing.pending = Some(Pending {
        sha256: code.hash(),
        expires: now.saturating_add(LIFETIME),
    });
    registry.check_admission().map_err(|e| e.to_string())?;
    store
        .commit(registry.revision(), &registry)
        .map_err(|e| e.to_string())?;
    Ok(code)
}

pub(crate) fn redeem(
    dir: &Path,
    request: Request,
    now: u64,
) -> std::result::Result<Option<Secret>, Error> {
    crate::enrollment::refuse_legacy_tokens(dir)?;
    let mut store = Store::open(dir)?;
    let mut registry = store.snapshot()?;
    let now = registry.latest.max(now);
    if now < registry.push_pairing.pause_until {
        return Ok(None);
    }
    let Some(pending) = registry.push_pairing.pending.take() else {
        return Ok(None);
    };
    registry.latest = now;
    let code = Secret::new(request.code);
    let token = if now >= pending.expires {
        None
    } else if !crate::credentials::ct_eq(&pending.sha256, &code.hash()) {
        registry.push_pairing.pause_until = now.saturating_add(PAUSE);
        None
    } else {
        let token = Secret::generate()?;
        registry.ensure_machine(&request.machine, None)?;
        let previous = registry
            .push_pairing
            .bearers
            .insert(request.machine.clone(), token.hash());
        registry.push_pairing.audit.push(Audit {
            time: now,
            machine: request.machine.clone(),
            action: if previous.is_some() {
                Action::Replace
            } else {
                Action::Pair
            },
        });
        registry.check_admission()?;
        crate::mirror::Receiver::prepare_machine(dir, &request.machine)
            .map_err(|_| Error::Custody)?;
        Some(token)
    };
    store.commit(registry.revision(), &registry)?;
    Ok(token)
}

pub(crate) fn response(token: &Secret) -> serde_json::Value {
    serde_json::json!({"bearer": token.expose()})
}

pub fn revoke(dir: &Path, machine: &str) -> Result<()> {
    crate::enrollment::refuse_legacy_tokens(dir).map_err(|e| e.to_string())?;
    let mut store = Store::open(dir).map_err(|e| e.to_string())?;
    let mut registry = store.snapshot().map_err(|e| e.to_string())?;
    if registry.push_pairing.bearers.remove(machine).is_none() {
        return Err("no active push pairing for that machine".into());
    }
    registry.latest = registry.latest.max(crate::origin_custody::now()?);
    registry.push_pairing.audit.push(Audit {
        time: registry.latest,
        machine: machine.to_owned(),
        action: Action::Revoke,
    });
    store
        .commit(registry.revision(), &registry)
        .map_err(|e| e.to_string())
}

pub fn pair(base: &Path, url: &str, code: String) -> Result<String> {
    let url = crate::check_url(url)?;
    if url.len() > CONFIG_CAP - CAP {
        return Err("receiver URL is too long for pair.json".into());
    }
    let code = Secret::new(code);
    if !valid_secret(code.expose()) {
        return Err("invalid pairing code".into());
    }
    crate::tokens::prepare_private_dir(base, true)?;
    let dir = CacheDirectory::open(base).map_err(|e| e.to_string())?;
    let machine = semon_sessions::machine_id::load_or_create().map_err(|e| e.to_string())?;
    let request = Request {
        machine: machine.clone(),
        code: code.expose().to_owned(),
    };
    let body = serde_json::to_vec(&request).map_err(|_| "cannot encode pairing request")?;
    let http = crate::http_transport(reqwest::blocking::Client::builder(), &url)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "cannot set up pairing connection")?;
    let response = http
        .post(format!("{url}{ROUTE}"))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .map_err(|_| "cannot reach pairing endpoint")?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!(
            "receiver refused pairing (HTTP {})",
            response.status().as_u16()
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take((CAP + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read pairing response")?;
    if bytes.len() > CAP {
        return Err("pairing response is too large".into());
    }
    let response: Response =
        serde_json::from_slice(&bytes).map_err(|_| "invalid pairing response")?;
    let config = Config {
        url,
        bearer: response.bearer,
    };
    if !valid_secret(&config.bearer) {
        return Err("invalid pairing Bearer".into());
    }
    save(&dir, &config)?;
    Ok(machine)
}

fn valid_secret(bearer: &str) -> bool {
    bearer.len() == 64 && bearer.bytes().all(|b| b.is_ascii_hexdigit())
}

fn save(dir: &CacheDirectory, config: &Config) -> Result<()> {
    let name = Path::new(CONFIG);
    let temp = format!(
        ".pair-{}",
        crate::enrollment::random_id().map_err(|e| e.to_string())?
    );
    let temp = Path::new(&temp);
    let bytes =
        Zeroizing::new(serde_json::to_vec(config).map_err(|_| "cannot encode pairing config")?);
    let mut file = dir
        .open_file(temp, libc::O_WRONLY | libc::O_EXCL | libc::O_CREAT)
        .map_err(|e| e.to_string())?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = dir.unlink(temp);
        return Err(error.to_string());
    }
    if let Err(error) = dir.rename(temp, name) {
        let _ = dir.unlink(temp);
        return Err(error.to_string());
    }
    dir.sync().map_err(|e| e.to_string())
}

pub fn load(base: &Path) -> Result<Option<(String, Credential)>> {
    if !base.try_exists().map_err(|e| e.to_string())? {
        return Ok(None);
    }
    let dir = CacheDirectory::open(base).map_err(|e| e.to_string())?;
    let Some(file) = dir
        .open_optional_file(Path::new(CONFIG), libc::O_RDONLY)
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((CONFIG_CAP + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > CONFIG_CAP {
        return Err("pair.json exceeds its size limit".into());
    }
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| "invalid pair.json")?;
    if !valid_secret(&config.bearer) {
        return Err("invalid Bearer in pair.json".into());
    }
    let url = crate::check_url(&config.url).map_err(|_| "invalid URL in pair.json")?;
    Ok(Some((url, Credential::Memory(Token::new(&config.bearer)?))))
}

pub fn forget(base: &Path) -> Result<()> {
    let dir = CacheDirectory::open(base).map_err(|e| e.to_string())?;
    dir.unlink(Path::new(CONFIG))
        .and_then(|()| dir.sync())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(crate::enrollment::random_id().unwrap());
            crate::tokens::prepare_private_dir(&dir, true).unwrap();
            Self(dir)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    const MACHINE: &str = "machine-0000000000000001";

    #[test]
    fn codes_expire_burn_replace_and_cannot_be_reused() {
        let fixture = Fixture::new();
        let dir = &fixture.0;
        Store::initialize(dir).unwrap();
        let redeem = |code: &Secret, now| {
            super::redeem(
                dir,
                Request {
                    machine: MACHINE.into(),
                    code: code.expose().into(),
                },
                now,
            )
            .unwrap()
        };
        let expired = issue_at(dir, 10).unwrap();
        assert!(redeem(&expired, 10 + LIFETIME).is_none());
        assert!(redeem(&expired, 10).is_none());
        let now = 11 + LIFETIME;
        let old = issue_at(dir, now).unwrap();
        let new = issue_at(dir, now).unwrap();
        assert_ne!(old.expose(), new.expose());
        assert!(redeem(&old, now).is_none());
        assert!(redeem(&new, now + 1).is_none());
        assert!(
            issue_at(dir, now + PAUSE - 1)
                .unwrap_err()
                .contains("paused")
        );
        assert!(issue_at(dir, 0).is_err());
        let persisted = Registry::read_current(dir).unwrap();
        assert_eq!(persisted.push_pairing.pause_until, now + PAUSE);
        assert!(persisted.push_pairing.pending.is_none());
        let current = issue_at(dir, now + PAUSE).unwrap();
        let token = redeem(&current, now + PAUSE).unwrap();
        assert!(redeem(&current, now + PAUSE).is_none());
        let registry = fs::read_to_string(dir.join("enrollment/registry.json")).unwrap();
        assert!(!registry.contains(current.expose()));
        assert!(!registry.contains(token.expose()));
    }

    #[test]
    fn tls_enrollment_can_open_a_push_paired_receiver() {
        let fixture = Fixture::new();
        let dir = &fixture.0;
        let code = issue(dir).unwrap();
        let token = redeem(
            dir,
            Request {
                machine: MACHINE.into(),
                code: code.expose().into(),
            },
            crate::origin_custody::now().unwrap(),
        )
        .unwrap()
        .unwrap();
        assert!(Registry::read_current(dir).unwrap().endpoint().is_none());
        let _controller = crate::provision::Controller::open(
            dir,
            "https://receiver.example:443",
            "laptop".into(),
        )
        .unwrap();
        let registry = Registry::read_current(dir).unwrap();
        assert_eq!(registry.endpoint(), Some("https://receiver.example:443"));
        assert_eq!(
            registry.push_pairing.machine(&token.hash()).as_deref(),
            Some(MACHINE)
        );
    }

    #[test]
    fn replaces_config_inode_with_private_complete_contents() {
        let fixture = Fixture::new();
        let dir = CacheDirectory::open(&fixture.0).unwrap();
        let path = fixture.0.join(CONFIG);
        let mut config = Config {
            url: "http://127.0.0.1:8735".into(),
            bearer: "a".repeat(64),
        };
        save(&dir, &config).unwrap();
        let old = fs::File::open(&path).unwrap();
        config.bearer = "b".repeat(64);
        save(&dir, &config).unwrap();
        let old: Config = serde_json::from_reader(old).unwrap();
        assert_eq!(old.bearer, "a".repeat(64));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let (url, credential) = load(&fixture.0).unwrap().unwrap();
        assert_eq!(url, config.url);
        assert_eq!(credential.token().unwrap().expose(), config.bearer);
        forget(&fixture.0).unwrap();
        assert!(load(&fixture.0).unwrap().is_none());
    }
}
