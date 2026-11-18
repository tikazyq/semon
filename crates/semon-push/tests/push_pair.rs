#![cfg(unix)]
use semon_push::{
    credentials::Kind,
    enrollment::Registry,
    push_pair::{self, Request},
    serve::{ConnectionAuthority, RegistryAuthenticator},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
const MACHINE: &str = "machine-6754a9c1e83f27b4";
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let f = Self(std::env::temp_dir().join(format!(
            "semon-pair-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        push_pair::initialize(&f.0).unwrap();
        f
    }
    fn redeem(
        &self,
        code: &str,
        now: u64,
    ) -> Result<push_pair::Response, semon_push::enrollment::Error> {
        push_pair::redeem(
            &self.0,
            &serde_json::to_vec(&Request {
                code: code.into(),
                machine: MACHINE.into(),
            })
            .unwrap(),
            now,
        )
    }
    fn accepts(&self, token: &str) -> bool {
        RegistryAuthenticator::open(&self.0)
            .unwrap()
            .authenticated_enrollment(
                &mut ConnectionAuthority::default(),
                Some(&format!("Bearer {token}")),
                Kind::MirrorPush,
                1000,
            )
            .is_some()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn replacement_consumption_expiry_and_persisted_pauses() {
    let f = Fixture::new();
    let old = push_pair::issue(&f.0, 100).unwrap();
    let new = push_pair::issue(&f.0, 101).unwrap();
    assert!(f.redeem(old.expose(), 102).is_err());
    assert!(push_pair::issue(&f.0, 131).is_err());
    // Wrong-code failure burns the replacement too, and the pause survives reopening.
    assert!(f.redeem(new.expose(), 132).is_err());
    assert!(push_pair::issue(&f.0, 161).is_err());
    let expires = push_pair::issue(&f.0, 162).unwrap();
    assert!(f.redeem(expires.expose(), 762).is_err());
    assert!(push_pair::issue(&f.0, 1061).is_err());
    let code = push_pair::issue(&f.0, 1062).unwrap();
    f.redeem(code.expose(), 1063).unwrap();
    assert!(f.redeem(code.expose(), 1064).is_err());
}
#[test]
fn newest_code_redeems_once_and_registry_rejects_old_format() {
    let f = Fixture::new();
    let first = push_pair::issue(&f.0, 100).unwrap();
    let second = push_pair::issue(&f.0, 101).unwrap();
    assert_ne!(first.expose(), second.expose());
    f.redeem(second.expose(), 102).unwrap();
    assert!(f.redeem(second.expose(), 103).is_err());
    let mut registry: serde_json::Value =
        serde_json::from_slice(&fs::read(f.0.join("enrollment/registry.json")).unwrap()).unwrap();
    registry["format"] = serde_json::json!(6);
    assert_eq!(
        Registry::parse(&serde_json::to_vec(&registry).unwrap()).unwrap_err(),
        semon_push::enrollment::Error::UnsupportedVersion
    );
}

#[test]
fn bearer_replacement_revocation_and_logs_preserved() {
    let f = Fixture::new();
    let code = push_pair::issue(&f.0, 100).unwrap();
    let first = f.redeem(code.expose(), 101).unwrap();
    assert!(f.accepts(&first.bearer));
    let auth = RegistryAuthenticator::open(&f.0).unwrap();
    let mut connection = ConnectionAuthority::default();
    let first_header = format!("Bearer {}", first.bearer);
    let held = auth
        .authenticated_enrollment(&mut connection, Some(&first_header), Kind::MirrorPush, 101)
        .unwrap()
        .authority;
    assert!(held.is_current_at(101));
    let log =
        f.0.join(format!("machines/{MACHINE}/claude/projects/test.jsonl"));
    fs::create_dir_all(log.parent().unwrap()).unwrap();
    fs::write(&log, "retained\n").unwrap();
    let code = push_pair::issue(&f.0, 102).unwrap();
    let second = f.redeem(code.expose(), 103).unwrap();
    assert!(!f.accepts(&first.bearer));
    assert!(!held.is_current_at(103));
    assert!(
        auth.authenticated_enrollment(&mut connection, Some(&first_header), Kind::MirrorPush, 103)
            .is_none()
    );
    assert!(f.accepts(&second.bearer));
    let bytes = fs::read(f.0.join("enrollment/registry.json")).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(&second.bearer));
    assert_eq!(Registry::parse(&bytes).unwrap().machines()[0].id, MACHINE);
    push_pair::revoke(&f.0, MACHINE, 104).unwrap();
    assert!(!f.accepts(&second.bearer));
    assert_eq!(fs::read_to_string(log).unwrap(), "retained\n");
}
#[test]
fn decoding_is_strict_and_bounded() {
    let f = Fixture::new();
    let code = push_pair::issue(&f.0, 100).unwrap();
    for bytes in [
        format!(
            r#"{{"code":"{}","machine":"{MACHINE}","extra":1}}"#,
            code.expose()
        ),
        format!(
            r#"{{"code":"{}","code":"x","machine":"{MACHINE}"}}"#,
            code.expose()
        ),
        " ".repeat(push_pair::MAX_BODY + 1),
        format!(r#"{{"code":"{}","machine":"../escape"}}"#, code.expose()),
    ] {
        assert!(push_pair::redeem(&f.0, bytes.as_bytes(), 101).is_err());
    }
    f.redeem(code.expose(), 102).unwrap();
}
#[test]
fn config_is_atomic_private_and_refuses_insecure_reads() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let f = Fixture::new();
    let path = f.0.join("config/pair.json");
    let mut c = semon_push::pair_config::Config {
        version: 1,
        url: "http://127.0.0.1:8735".into(),
        machine: MACHINE.into(),
        bearer: "a".repeat(64),
    };
    c.save(&path).unwrap();
    let old = fs::File::open(&path).unwrap();
    let inode = old.metadata().unwrap().ino();
    c.bearer = "b".repeat(64);
    c.save(&path).unwrap();
    assert_ne!(inode, fs::metadata(&path).unwrap().ino());
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        semon_push::pair_config::Config::load(&path)
            .unwrap()
            .unwrap()
            .bearer,
        c.bearer
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(semon_push::pair_config::Config::load(&path).is_err());
    for url in [
        "http://example.com",
        "http://192.168.1.2",
        "http://127.0.0.1.evil.test",
    ] {
        assert!(semon_push::pair_config::pair(url, "code", MACHINE).is_err());
    }
}
