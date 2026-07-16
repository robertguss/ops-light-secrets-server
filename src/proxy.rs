//! Fail-closed listener classification and reverse-proxy client attribution.

use axum::http::{HeaderMap, header::HeaderName};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerType {
    Direct,
    ReverseProxyTcp { trusted_peer: IpAddr },
    ReverseProxyUnix { trusted_uid: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportSecurity {
    Plaintext,
    Tls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindPolicyError {
    NoResolvedAddress,
    RemotePlaintext,
    ProxyBackendNotLoopback,
    ProxyPeerNotLoopback,
    UnixListenerHasTcpAddress,
}

impl fmt::Display for BindPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NoResolvedAddress => "listener resolved no addresses",
            Self::RemotePlaintext => "plaintext listener resolved a non-loopback address",
            Self::ProxyBackendNotLoopback => "reverse-proxy TCP backend is not loopback-only",
            Self::ProxyPeerNotLoopback => "configured reverse-proxy peer is not loopback",
            Self::UnixListenerHasTcpAddress => "Unix reverse-proxy listener has TCP addresses",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BindPolicyError {}

/// Validate every address returned by name resolution before any bind occurs.
pub fn validate_resolved_tcp_addresses(
    addresses: &[SocketAddr],
    security: TransportSecurity,
    listener: ListenerType,
) -> Result<(), BindPolicyError> {
    match listener {
        ListenerType::ReverseProxyUnix { .. } => {
            return if addresses.is_empty() {
                Ok(())
            } else {
                Err(BindPolicyError::UnixListenerHasTcpAddress)
            };
        }
        _ if addresses.is_empty() => return Err(BindPolicyError::NoResolvedAddress),
        _ => {}
    }

    match listener {
        ListenerType::Direct => {
            if security == TransportSecurity::Plaintext
                && addresses.iter().any(|address| !is_loopback(address.ip()))
            {
                return Err(BindPolicyError::RemotePlaintext);
            }
        }
        ListenerType::ReverseProxyTcp { trusted_peer } => {
            if !is_loopback(trusted_peer) {
                return Err(BindPolicyError::ProxyPeerNotLoopback);
            }
            if addresses.iter().any(|address| !is_loopback(address.ip())) {
                return Err(BindPolicyError::ProxyBackendNotLoopback);
            }
        }
        ListenerType::ReverseProxyUnix { .. } => unreachable!(),
    }
    Ok(())
}

/// Loopback classification also recognizes IPv4 embedded in IPv6.
pub fn is_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => {
            address
                .to_ipv4_mapped()
                .is_some_and(|mapped| mapped.is_loopback())
                || address.is_loopback()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerIdentity {
    Tcp(SocketAddr),
    Unix { uid: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientSource(IpAddr);

impl ClientSource {
    pub fn address(self) -> IpAddr {
        self.0
    }

    /// Stable source used by the attempt-rate bucket.
    pub fn rate_limit_key(self) -> IpAddr {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardedSourceError {
    PeerKindMismatch,
    UntrustedUnixPeer,
    Missing,
    Duplicate,
    InvalidEncoding,
    NonCanonical,
}

impl fmt::Display for ForwardedSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::PeerKindMismatch => "listener and transport peer kinds differ",
            Self::UntrustedUnixPeer => "Unix proxy peer has the wrong owner",
            Self::Missing => "trusted proxy omitted X-Forwarded-For",
            Self::Duplicate => "trusted proxy supplied multiple X-Forwarded-For headers",
            Self::InvalidEncoding => "X-Forwarded-For is not valid header text",
            Self::NonCanonical => "X-Forwarded-For is not one canonical IP address",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ForwardedSourceError {}

/// Resolve one request's rate-limit source before authentication or handling.
pub fn resolve_client_source(
    listener: ListenerType,
    peer: PeerIdentity,
    headers: &HeaderMap,
) -> Result<ClientSource, ForwardedSourceError> {
    match (listener, peer) {
        (ListenerType::Direct, PeerIdentity::Tcp(peer)) => Ok(ClientSource(peer.ip())),
        (ListenerType::ReverseProxyTcp { trusted_peer }, PeerIdentity::Tcp(observed_peer))
            if observed_peer.ip() != trusted_peer =>
        {
            Ok(ClientSource(observed_peer.ip()))
        }
        (ListenerType::ReverseProxyTcp { .. }, PeerIdentity::Tcp(_)) => {
            parse_forwarded_source(headers).map(ClientSource)
        }
        (ListenerType::ReverseProxyUnix { trusted_uid }, PeerIdentity::Unix { uid })
            if uid == trusted_uid =>
        {
            parse_forwarded_source(headers).map(ClientSource)
        }
        (ListenerType::ReverseProxyUnix { .. }, PeerIdentity::Unix { .. }) => {
            Err(ForwardedSourceError::UntrustedUnixPeer)
        }
        _ => Err(ForwardedSourceError::PeerKindMismatch),
    }
}

fn parse_forwarded_source(headers: &HeaderMap) -> Result<IpAddr, ForwardedSourceError> {
    let values: Vec<_> = headers.get_all(&X_FORWARDED_FOR).iter().collect();
    let value = match values.as_slice() {
        [] => return Err(ForwardedSourceError::Missing),
        [value] => value
            .to_str()
            .map_err(|_| ForwardedSourceError::InvalidEncoding)?,
        _ => return Err(ForwardedSourceError::Duplicate),
    };
    if value.contains(',') {
        return Err(ForwardedSourceError::NonCanonical);
    }
    let address: IpAddr = value
        .parse()
        .map_err(|_| ForwardedSourceError::NonCanonical)?;
    if address.to_string() != value {
        return Err(ForwardedSourceError::NonCanonical);
    }
    Ok(address)
}
