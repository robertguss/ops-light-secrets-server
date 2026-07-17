//! Fixed-memory request limiting and bounded flood accounting.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, StatusCode, header::CONTENT_LENGTH};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::auth::AuthenticatedToken;
use crate::proxy::ClientSource;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum UnauthenticatedClass {
    Login,
    Probe,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DropReason {
    Rate,
    Oversize,
    Malformed,
    Concurrency,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AggregateClass {
    Login,
    Probe,
    Authenticated,
    Overflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DropAggregate {
    pub class: AggregateClass,
    pub reason: DropReason,
    pub bucket_id: u16,
    pub count: u64,
    pub window_start_milliseconds: u64,
    pub window_end_milliseconds: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    pub window_milliseconds: u64,
    pub global_attempts: u32,
    pub login_attempts: u32,
    pub probe_attempts: u32,
    pub identity_attempts: u32,
    pub source_shards: usize,
    pub identity_shards: usize,
    pub max_aggregates: usize,
    pub unauthenticated_body_bytes: u64,
    pub authenticated_body_bytes: u64,
    pub authenticated_concurrency: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window_milliseconds: 60_000,
            global_attempts: 10_000,
            login_attempts: 20,
            probe_attempts: 120,
            identity_attempts: 600,
            source_shards: 256,
            identity_shards: 256,
            max_aggregates: 1_024,
            unauthenticated_body_bytes: 64 * 1024,
            authenticated_body_bytes: 1024 * 1024,
            authenticated_concurrency: 128,
        }
    }
}

impl RateLimitConfig {
    fn validate(self) -> Result<Self, RateLimitError> {
        if self.window_milliseconds == 0
            || self.global_attempts == 0
            || self.login_attempts == 0
            || self.probe_attempts == 0
            || self.identity_attempts == 0
            || self.source_shards == 0
            || self.source_shards > usize::from(u16::MAX)
            || self.identity_shards == 0
            || self.identity_shards > usize::from(u16::MAX)
            || self.max_aggregates == 0
            || self.unauthenticated_body_bytes == 0
            || self.authenticated_body_bytes == 0
            || self.authenticated_concurrency == 0
        {
            return Err(RateLimitError::InvalidConfig);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitError {
    InvalidConfig,
    RateLimited,
    Oversize,
    Concurrency,
    Internal,
}

#[derive(Clone, Copy, Default)]
struct Bucket {
    window: u64,
    used: u32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AggregateKey {
    class: AggregateClass,
    reason: DropReason,
    bucket_id: u16,
    window: u64,
}

struct LimiterState {
    global: Bucket,
    login: Vec<Bucket>,
    probe: Vec<Bucket>,
    identity: Vec<Bucket>,
    aggregates: BTreeMap<AggregateKey, u64>,
}

struct Inner {
    config: RateLimitConfig,
    hash_key: [u8; 32],
    started: Instant,
    state: Mutex<LimiterState>,
    concurrency: Arc<Semaphore>,
}

#[derive(Clone)]
pub struct RateLimitService(Arc<Inner>);

impl RateLimitService {
    pub fn new(config: RateLimitConfig, hash_key: [u8; 32]) -> Result<Self, RateLimitError> {
        let config = config.validate()?;
        Ok(Self(Arc::new(Inner {
            config,
            hash_key,
            started: Instant::now(),
            state: Mutex::new(LimiterState {
                global: Bucket::default(),
                login: vec![Bucket::default(); config.source_shards],
                probe: vec![Bucket::default(); config.source_shards],
                identity: vec![Bucket::default(); config.identity_shards],
                aggregates: BTreeMap::new(),
            }),
            concurrency: Arc::new(Semaphore::new(config.authenticated_concurrency)),
        })))
    }

    pub fn fixed_bucket_count(&self) -> usize {
        1 + self.0.config.source_shards * 2 + self.0.config.identity_shards
    }

    pub fn config(&self) -> RateLimitConfig {
        self.0.config
    }

    pub fn now_milliseconds(&self) -> u64 {
        u64::try_from(self.0.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub fn check_unauthenticated(
        &self,
        class: UnauthenticatedClass,
        source: Option<IpAddr>,
        now_milliseconds: u64,
    ) -> Result<u16, RateLimitError> {
        let window = now_milliseconds / self.0.config.window_milliseconds;
        let bucket_id = self.source_bucket(source);
        let mut state = self.0.state.lock().map_err(|_| RateLimitError::Internal)?;
        if !consume(&mut state.global, window, self.0.config.global_attempts) {
            self.record_locked(
                &mut state,
                class.into(),
                DropReason::Rate,
                bucket_id,
                window,
            );
            return Err(RateLimitError::RateLimited);
        }
        let (buckets, allowance) = match class {
            UnauthenticatedClass::Login => (&mut state.login, self.0.config.login_attempts),
            UnauthenticatedClass::Probe => (&mut state.probe, self.0.config.probe_attempts),
        };
        if !consume(&mut buckets[usize::from(bucket_id)], window, allowance) {
            self.record_locked(
                &mut state,
                class.into(),
                DropReason::Rate,
                bucket_id,
                window,
            );
            return Err(RateLimitError::RateLimited);
        }
        Ok(bucket_id)
    }

    pub fn check_authenticated(
        &self,
        identity_id: [u8; 16],
        now_milliseconds: u64,
    ) -> Result<u16, RateLimitError> {
        let window = now_milliseconds / self.0.config.window_milliseconds;
        let bucket_id = self.identity_bucket(identity_id);
        let mut state = self.0.state.lock().map_err(|_| RateLimitError::Internal)?;
        if !consume(
            &mut state.identity[usize::from(bucket_id)],
            window,
            self.0.config.identity_attempts,
        ) {
            self.record_locked(
                &mut state,
                AggregateClass::Authenticated,
                DropReason::Rate,
                bucket_id,
                window,
            );
            return Err(RateLimitError::RateLimited);
        }
        Ok(bucket_id)
    }

    pub fn record_drop(
        &self,
        class: AggregateClass,
        reason: DropReason,
        bucket_id: u16,
        now_milliseconds: u64,
    ) {
        if let Ok(mut state) = self.0.state.lock() {
            self.record_locked(
                &mut state,
                class,
                reason,
                bucket_id,
                now_milliseconds / self.0.config.window_milliseconds,
            );
        }
    }

    pub fn take_aggregates(&self) -> Vec<DropAggregate> {
        let Ok(mut state) = self.0.state.lock() else {
            return Vec::new();
        };
        let aggregates = std::mem::take(&mut state.aggregates);
        aggregates
            .into_iter()
            .map(|(key, count)| self.aggregate(key, count))
            .collect()
    }

    pub fn aggregate_slots(&self) -> usize {
        self.0
            .state
            .lock()
            .map_or(self.0.config.max_aggregates, |state| state.aggregates.len())
    }

    fn source_bucket(&self, source: Option<IpAddr>) -> u16 {
        source.map_or(0, |source| {
            self.hash_bucket(
                b"source\0",
                source.to_string().as_bytes(),
                self.0.config.source_shards,
            )
        })
    }

    fn identity_bucket(&self, identity_id: [u8; 16]) -> u16 {
        self.hash_bucket(b"identity\0", &identity_id, self.0.config.identity_shards)
    }

    fn hash_bucket(&self, domain: &[u8], value: &[u8], count: usize) -> u16 {
        let mut hasher = blake3::Hasher::new_keyed(&self.0.hash_key);
        hasher.update(domain);
        hasher.update(value);
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
        u16::try_from((u64::from_le_bytes(bytes) % count as u64) as usize)
            .expect("validated shard count fits u16")
    }

    fn record_locked(
        &self,
        state: &mut LimiterState,
        class: AggregateClass,
        reason: DropReason,
        bucket_id: u16,
        window: u64,
    ) {
        let mut key = AggregateKey {
            class,
            reason,
            bucket_id,
            window,
        };
        if !state.aggregates.contains_key(&key)
            && state.aggregates.len() >= self.0.config.max_aggregates
        {
            key = AggregateKey {
                class: AggregateClass::Overflow,
                reason,
                bucket_id: u16::MAX,
                window,
            };
            if !state.aggregates.contains_key(&key)
                && state.aggregates.len() >= self.0.config.max_aggregates
            {
                let oldest = state.aggregates.keys().next().copied();
                if let Some(oldest) = oldest {
                    let count = state.aggregates.remove(&oldest).unwrap_or(0);
                    *state.aggregates.entry(key).or_insert(0) += count;
                }
            }
        }
        *state.aggregates.entry(key).or_insert(0) += 1;
    }

    fn aggregate(&self, key: AggregateKey, count: u64) -> DropAggregate {
        let start = key.window.saturating_mul(self.0.config.window_milliseconds);
        DropAggregate {
            class: key.class,
            reason: key.reason,
            bucket_id: key.bucket_id,
            count,
            window_start_milliseconds: start,
            window_end_milliseconds: start
                .saturating_add(self.0.config.window_milliseconds.saturating_sub(1)),
        }
    }

    fn try_concurrency(&self) -> Result<OwnedSemaphorePermit, RateLimitError> {
        self.0
            .concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| RateLimitError::Concurrency)
    }
}

impl From<UnauthenticatedClass> for AggregateClass {
    fn from(value: UnauthenticatedClass) -> Self {
        match value {
            UnauthenticatedClass::Login => Self::Login,
            UnauthenticatedClass::Probe => Self::Probe,
        }
    }
}

fn consume(bucket: &mut Bucket, window: u64, allowance: u32) -> bool {
    if bucket.window != window {
        bucket.window = window;
        bucket.used = 0;
    }
    if bucket.used >= allowance {
        return false;
    }
    bucket.used += 1;
    true
}

pub async fn pre_verifier_guard(
    State(limiter): State<RateLimitService>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let class = match request.uri().path() {
        "/v1/auth/approle/login" => Some(UnauthenticatedClass::Login),
        "/v1/sys/health" | "/v1/sys/seal-status" => Some(UnauthenticatedClass::Probe),
        _ => None,
    };
    let Some(class) = class else {
        return next.run(request).await;
    };
    let now = limiter.now_milliseconds();
    let source = request
        .extensions()
        .get::<ClientSource>()
        .copied()
        .map(ClientSource::rate_limit_key);
    let bucket = match limiter.check_unauthenticated(class, source, now) {
        Ok(bucket) => bucket,
        Err(_) => return limited_response(),
    };
    let body_limit = limiter.0.config.unauthenticated_body_bytes;
    if content_length(&request) > Some(body_limit) {
        limiter.record_drop(class.into(), DropReason::Oversize, bucket, now);
        return payload_response();
    }
    let Ok(request) = bounded_request(request, body_limit).await else {
        limiter.record_drop(class.into(), DropReason::Oversize, bucket, now);
        return payload_response();
    };
    let response = next.run(request).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        limiter.record_drop(class.into(), DropReason::Oversize, bucket, now);
    } else if response.status() == StatusCode::BAD_REQUEST
        && response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/plain"))
    {
        limiter.record_drop(class.into(), DropReason::Malformed, bucket, now);
    }
    response
}

pub async fn authenticated_guard(
    State(limiter): State<RateLimitService>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(identity) = request.extensions().get::<AuthenticatedToken>().copied() else {
        return forbidden_response();
    };
    let now = limiter.now_milliseconds();
    let bucket = match limiter.check_authenticated(identity.identity_id, now) {
        Ok(bucket) => bucket,
        Err(_) => return limited_response(),
    };
    let body_limit = limiter.0.config.authenticated_body_bytes;
    if content_length(&request) > Some(body_limit) {
        limiter.record_drop(
            AggregateClass::Authenticated,
            DropReason::Oversize,
            bucket,
            now,
        );
        return payload_response();
    }
    let Ok(request) = bounded_request(request, body_limit).await else {
        limiter.record_drop(
            AggregateClass::Authenticated,
            DropReason::Oversize,
            bucket,
            now,
        );
        return payload_response();
    };
    let Ok(_permit) = limiter.try_concurrency() else {
        limiter.record_drop(
            AggregateClass::Authenticated,
            DropReason::Concurrency,
            bucket,
            now,
        );
        return limited_response();
    };
    next.run(request).await
}

fn content_length(request: &Request<Body>) -> Option<u64> {
    request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

async fn bounded_request(request: Request<Body>, limit: u64) -> Result<Request<Body>, ()> {
    let limit = usize::try_from(limit).map_err(|_| ())?;
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, limit).await.map_err(|_| ())?;
    Ok(Request::from_parts(parts, Body::from(bytes)))
}

fn limited_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"errors": ["rate limit exceeded"]})),
    )
        .into_response()
}

fn payload_response() -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({"errors": ["request body too large"]})),
    )
        .into_response()
}

fn forbidden_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"errors": ["permission denied"]})),
    )
        .into_response()
}
