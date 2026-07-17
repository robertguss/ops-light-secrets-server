#[test]
fn hardened_systemd_examples_exist_and_refuse_env_secrets() {
    let service = include_str!("../examples/systemd/ops-light-secrets-server.service");
    assert!(service.contains("NoNewPrivileges=yes"));
    assert!(service.contains("ProtectSystem=strict"));
    assert!(service.contains("ExecStart="));
    assert!(!service.to_lowercase().contains("age-secret-key"));
    assert!(!service.contains("Environment=OLSS_AGE_IDENTITY"));
    let socket = include_str!("../examples/systemd/ops-light-secrets-server-control.socket");
    assert!(socket.contains("SocketMode=0600"));
    let operating = std::fs::read_to_string("docs/operating.md").unwrap();
    assert!(operating.contains("examples/systemd") || operating.contains("systemd"));
}
