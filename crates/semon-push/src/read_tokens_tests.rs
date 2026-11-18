use super::*;
use crate::{enrollment::Store, simple_pair};
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "semon-read-token-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        simple_pair::initialize(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn credentials_are_separate_hashed_audited_and_terminal() {
    let f = Fixture::new();
    let (code, _) = simple_pair::issue(&f.0, 100).unwrap();
    let (id, secret) = create(&f.0, 101).unwrap();
    let request = |code: &str| {
        serde_json::to_vec(&simple_pair::Request {
            version: 1,
            code: code.into(),
            machine_id: "machine-6754a9c1e83f27b4".into(),
            hostname: "laptop".into(),
        })
        .unwrap()
    };
    assert!(simple_pair::pair(&f.0, &request(secret.expose()), 102).is_err());
    let paired = simple_pair::pair(&f.0, &request(code.expose()), 103).unwrap();
    let registry = Registry::read_current(&f.0).unwrap();
    assert_eq!(registry.read_token(secret.expose()).unwrap().id, id);
    assert!(registry.read_token(&paired.token).is_none());
    assert!(registry.read_token(code.expose()).is_none());
    assert!(registry.paired_token(&secret).is_none());
    assert!(
        simple_pair::unpair_token(&f.0, Some(&format!("Bearer {}", secret.expose())), 104).is_err()
    );
    let bytes = fs::read(f.0.join("enrollment/registry.json")).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(secret.expose()));
    assert_eq!(registry.read_token_audit.len(), 1);
    assert_eq!(list(&f.0).unwrap().len(), 1);
    let store = Store::open(&f.0).unwrap();
    let old = store.snapshot().unwrap();
    drop(store);
    revoke(&f.0, &id, 105).unwrap();
    let revoked = Registry::read_current(&f.0).unwrap();
    assert!(revoked.read_token(secret.expose()).is_none());
    assert_eq!(revoked.read_token_audit.len(), 2);
    assert_eq!(list(&f.0).unwrap()[0].revoked_at, Some(105));
    let mut store = Store::open(&f.0).unwrap();
    assert_eq!(store.commit(revoked.revision(), &old), Err(Error::Terminal));
    let mut version: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    version["format"] = serde_json::json!(7);
    assert_eq!(
        Registry::parse(&serde_json::to_vec(&version).unwrap()),
        Err(Error::UnsupportedVersion)
    );
}
