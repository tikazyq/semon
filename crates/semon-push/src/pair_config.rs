//! Atomic private custody for the simple push pairing.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const CAP: u64 = 4096;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub url: String,
    pub machine: String,
    pub bearer: String,
}
pub fn path() -> Result<PathBuf, String> {
    let origin = crate::origin_custody::default_directory()?;
    Ok(origin
        .parent()
        .ok_or("config directory has no parent")?
        .join("pair.json"))
}
impl Config {
    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || !semon_sessions::machine_id::valid(&self.machine)
            || crate::check_url(&self.url)? != self.url
            || self.bearer.len() != 64
            || !self.bearer.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("invalid pair.json".into());
        }
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
            return Err("pair.json must be a private owned regular file".into());
        }
        let mut bytes = Vec::new();
        file.take(CAP + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > CAP {
            return Err("pair.json too large".into());
        }
        let config: Self = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        config.validate()?;
        Ok(Some(config))
    }
    pub fn save(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > CAP {
            return Err("pair.json too large".into());
        }
        let parent = path.parent().ok_or("pair.json has no parent")?;
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| e.to_string())?;
        let meta = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
        if !meta.is_dir() || meta.mode() & 0o022 != 0 || meta.uid() != unsafe { libc::geteuid() } {
            return Err("pair.json directory must be owned and not writable by others".into());
        }
        let stage = parent.join(format!(
            ".pair-{}",
            crate::enrollment::random_id().map_err(|e| e.to_string())?
        ));
        let result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&stage)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&stage, path)?;
            fs::File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(stage);
        }
        result.map_err(|e| e.to_string())
    }
    pub fn credential(&self) -> Result<crate::Credential, String> {
        Ok(crate::Credential::Memory(crate::Token::new(&self.bearer)?))
    }
}
pub fn pair(url: &str, code: &str, machine: &str) -> Result<Config, String> {
    let url = crate::check_url(url)?;
    let request = crate::push_pair::Request {
        code: code.into(),
        machine: machine.into(),
    };
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let body = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    if body.len() > crate::push_pair::MAX_BODY {
        return Err("pairing request too large".into());
    }
    let response = client
        .post(format!("{url}/v1/pair"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .map_err(|e| e.to_string())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("pairing refused ({})", response.status()));
    }
    let mut bytes = Vec::new();
    response
        .take(CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > CAP {
        return Err("pairing response too large".into());
    }
    let response: crate::push_pair::Response =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if response.machine != machine {
        return Err("pairing machine mismatch".into());
    }
    let config = Config {
        version: 1,
        url,
        machine: response.machine,
        bearer: response.bearer,
    };
    config.validate()?;
    Ok(config)
}
