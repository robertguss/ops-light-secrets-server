use axum::http::{HeaderMap, HeaderValue};
use ops_light_secrets_server::control::{OwnerUnixListener, PeerAudit, PeerRefusal, data_router};
use ops_light_secrets_server::proxy::{
    BindPolicyError, ForwardedSourceError, ListenerType, PeerIdentity, TransportSecurity,
    is_loopback, resolve_client_source, validate_resolved_tcp_addresses,
};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Audit;

impl PeerAudit for Audit {
    fn peer_refused(&self, _: PeerRefusal) {}
}

fn headers(values: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for value in values {
        headers.append(
            "x-forwarded-for",
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    headers
}

#[test]
fn plaintext_and_proxy_backends_are_classified_across_all_resolved_addresses() {
    let loopbacks: Vec<SocketAddr> = vec![
        "127.42.0.1:8200".parse().unwrap(),
        "[::1]:8200".parse().unwrap(),
        "[::ffff:127.0.0.1]:8200".parse().unwrap(),
    ];
    assert!(loopbacks.iter().all(|address| is_loopback(address.ip())));
    assert_eq!(
        validate_resolved_tcp_addresses(
            &loopbacks,
            TransportSecurity::Plaintext,
            ListenerType::Direct,
        ),
        Ok(())
    );

    let mixed: Vec<SocketAddr> = vec![
        "127.0.0.1:8200".parse().unwrap(),
        "192.0.2.1:8200".parse().unwrap(),
    ];
    assert_eq!(
        validate_resolved_tcp_addresses(&mixed, TransportSecurity::Plaintext, ListenerType::Direct,),
        Err(BindPolicyError::RemotePlaintext)
    );
    assert_eq!(
        validate_resolved_tcp_addresses(
            &mixed,
            TransportSecurity::Tls,
            ListenerType::ReverseProxyTcp {
                trusted_peer: "127.0.0.1".parse().unwrap(),
            },
        ),
        Err(BindPolicyError::ProxyBackendNotLoopback)
    );
    assert_eq!(
        validate_resolved_tcp_addresses(
            &loopbacks,
            TransportSecurity::Plaintext,
            ListenerType::ReverseProxyTcp {
                trusted_peer: "192.0.2.2".parse().unwrap(),
            },
        ),
        Err(BindPolicyError::ProxyPeerNotLoopback)
    );
    assert_eq!(
        validate_resolved_tcp_addresses(&[], TransportSecurity::Tls, ListenerType::Direct),
        Err(BindPolicyError::NoResolvedAddress)
    );
}

#[test]
fn trusted_proxy_accepts_exactly_one_canonical_address() {
    let listener = ListenerType::ReverseProxyTcp {
        trusted_peer: "127.0.0.2".parse().unwrap(),
    };
    let peer = PeerIdentity::Tcp("127.0.0.2:40000".parse().unwrap());
    for canonical in ["192.0.2.5", "2001:db8::5", "::ffff:192.0.2.5"] {
        let mut request_headers = headers(&[canonical]);
        request_headers.insert("forwarded", HeaderValue::from_static("for=203.0.113.4"));
        request_headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.5"));
        let source = resolve_client_source(listener, peer, &request_headers).unwrap();
        assert_eq!(source.address(), canonical.parse::<IpAddr>().unwrap());
        assert_eq!(source.rate_limit_key(), source.address());
    }
    for (values, error) in [
        (vec![], ForwardedSourceError::Missing),
        (
            vec!["192.0.2.1", "192.0.2.2"],
            ForwardedSourceError::Duplicate,
        ),
        (
            vec!["192.0.2.1, 192.0.2.2"],
            ForwardedSourceError::NonCanonical,
        ),
        (vec!["192.0.2.1:80"], ForwardedSourceError::NonCanonical),
        (vec!["[2001:db8::1]"], ForwardedSourceError::NonCanonical),
        (vec!["2001:0db8::1"], ForwardedSourceError::NonCanonical),
        (vec![" 192.0.2.1"], ForwardedSourceError::NonCanonical),
    ] {
        assert_eq!(
            resolve_client_source(listener, peer, &headers(&values)),
            Err(error)
        );
    }
}

#[test]
fn derived_source_is_recomputed_for_each_request() {
    let listener = ListenerType::ReverseProxyTcp {
        trusted_peer: "127.0.0.2".parse().unwrap(),
    };
    let peer = PeerIdentity::Tcp("127.0.0.2:40000".parse().unwrap());
    let first = resolve_client_source(listener, peer, &headers(&["192.0.2.1"]))
        .unwrap()
        .address();
    let second = resolve_client_source(listener, peer, &headers(&["192.0.2.2"]))
        .unwrap()
        .address();
    assert_eq!(first, "192.0.2.1".parse::<IpAddr>().unwrap());
    assert_eq!(second, "192.0.2.2".parse::<IpAddr>().unwrap());
}

#[test]
fn forwarding_metadata_is_ignored_in_direct_mode_and_from_wrong_tcp_peer() {
    let mut untrusted = headers(&["198.51.100.9", "203.0.113.9"]);
    untrusted.insert("forwarded", HeaderValue::from_static("for=203.0.113.4"));
    untrusted.insert("x-real-ip", HeaderValue::from_static("203.0.113.5"));

    let direct_peer = "192.0.2.4:45000".parse().unwrap();
    assert_eq!(
        resolve_client_source(
            ListenerType::Direct,
            PeerIdentity::Tcp(direct_peer),
            &untrusted,
        )
        .unwrap()
        .address(),
        direct_peer.ip()
    );
    let proxy_peer = "127.0.0.3:45000".parse().unwrap();
    assert_eq!(
        resolve_client_source(
            ListenerType::ReverseProxyTcp {
                trusted_peer: "127.0.0.2".parse().unwrap(),
            },
            PeerIdentity::Tcp(proxy_peer),
            &untrusted,
        )
        .unwrap()
        .address(),
        proxy_peer.ip()
    );
}

#[test]
fn unix_proxy_requires_verified_uid_before_using_forwarded_source() {
    let listener = ListenerType::ReverseProxyUnix { trusted_uid: 1000 };
    assert_eq!(
        resolve_client_source(
            listener,
            PeerIdentity::Unix { uid: 1001 },
            &headers(&["192.0.2.1"]),
        ),
        Err(ForwardedSourceError::UntrustedUnixPeer)
    );
    assert_eq!(
        resolve_client_source(
            listener,
            PeerIdentity::Unix { uid: 1000 },
            &headers(&["192.0.2.1"]),
        )
        .unwrap()
        .address(),
        "192.0.2.1".parse::<IpAddr>().unwrap()
    );
}

#[tokio::test]
async fn unix_proxy_data_socket_reuses_owner_only_socket_discipline() {
    let directory = tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("proxy.sock");
    let uid = unsafe { libc::geteuid() };
    let listener = OwnerUnixListener::bind(&path, uid, Arc::new(Audit)).unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, data_router()).await });
    let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
    client
        .write_all(b"GET /v1/sys/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    server.abort();
    let _ = server.await;
    assert!(!path.exists());
}
