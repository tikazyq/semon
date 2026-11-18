use super::*;

fn shared(dir: &Path, limits: Limits) -> Arc<Shared> {
    Arc::new(Shared {
        receiver: Receiver::new(dir.to_path_buf()).unwrap(),
        tokens: Authenticator::open(dir).unwrap(),
        tls: None,
        limits,
        viewer: None,
        admission: Mutex::new(Admission::default()),
        body: None,
        provisioning: None,
        provisioning_clock: None,
        provisioning_timeout: None,
        provisioning_terminal: None,
    })
}

#[test]
fn viewer_slots_leave_the_tunnel_peers_push_allowance_and_total_capacity() {
    let dir = auth_tests::PrivateDir::new();
    crate::simple_pair::initialize(&dir.0).unwrap();
    let shared = shared(
        &dir.0,
        Limits {
            connections: 8,
            connections_per_ip: 2,
            ..Limits::default()
        },
    );
    let ip = "127.0.0.1".parse().unwrap();
    let mut viewers = Vec::new();
    for _ in 0..4 {
        let mut slot = Slot::admit(&shared, ip).unwrap();
        assert!(slot.admit_viewer());
        viewers.push(slot);
    }
    assert_eq!(shared.admission().open, 4);
    assert_eq!(shared.admission().per_ip.get(&ip), None);
    let mut over = Slot::admit(&shared, ip).unwrap();
    assert!(!over.admit_viewer());
    drop(over);
    let mut push = Slot::admit(&shared, ip).unwrap();
    push.authenticated();
    let pending = Slot::admit(&shared, ip).unwrap();
    let pending2 = Slot::admit(&shared, ip).unwrap();
    assert!(Slot::admit(&shared, ip).is_none());
    drop((pending, pending2, push, viewers));
    assert_eq!(shared.admission().open, 0);
    assert_eq!(shared.admission().viewer, 0);
}

#[test]
fn public_origin_is_exact_and_loopback_stays_available() {
    let dir = auth_tests::PrivateDir::new();
    let viewer = Viewer::new(
        &dir.0,
        "127.0.0.1:8735".parse().unwrap(),
        Some("https://history.example:8443"),
        false,
    )
    .unwrap();
    let head = |host: &str, origin: Option<&str>| Head {
        host: Some(host.into()),
        origin: origin.map(str::to_owned),
        ..Head::default()
    };
    assert!(viewer.allowed(&head(
        "history.example:8443",
        Some("https://history.example:8443")
    )));
    assert!(viewer.allowed(&head("localhost:8735", Some("http://localhost:8735"))));
    assert!(!viewer.allowed(&head("history.example", None)));
    assert!(!viewer.allowed(&head(
        "history.example:8443",
        Some("http://history.example:8443")
    )));
    assert!(!viewer.allowed(&head("history.example.evil:8443", None)));
    assert!(
        Viewer::new(
            &dir.0,
            "127.0.0.1:8735".parse().unwrap(),
            Some("https://history.example/path"),
            false
        )
        .is_err()
    );
    let cookie = viewer.cookie("test-id");
    assert_eq!(viewer.cookie_id(&cookie), Some("test-id"));
    assert_eq!(
        viewer.cookie_id(&cookie.replace("test-id", "other-id")),
        None
    );
}
