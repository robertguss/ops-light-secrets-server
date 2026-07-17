//! Ambiguity-rejecting request deserialization boundaries.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt;
use std::rc::Rc;

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, header::HeaderName};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use zeroize::Zeroizing;

pub const MAX_JSON_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_JSON_KEYS: usize = 1024;
pub const MAX_JSON_VALUES: usize = 4096;
pub const MAX_HEADER_FIELDS: usize = 128;
pub const MAX_HEADER_BYTES: usize = 32 * 1024;
pub const MAX_QUERY_PARAMETERS: usize = 2;

const DUPLICATE_KEY_MARKER: &str = "duplicate-json-key";
const DEPTH_MARKER: &str = "json-depth-limit";
const KEY_LIMIT_MARKER: &str = "json-key-limit";
const VALUE_LIMIT_MARKER: &str = "json-value-limit";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryShapeReason {
    Duplicate,
    NoncanonicalName,
    UnknownName,
    TooMany,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryShapeError {
    pub reason: QueryShapeReason,
    pub offset: usize,
}

pub fn validate_sensitive_query(raw: Option<&str>) -> Result<(), QueryShapeError> {
    let Some(raw) = raw else {
        return Ok(());
    };
    if raw.is_empty() {
        return Err(QueryShapeError {
            reason: QueryShapeReason::Invalid,
            offset: 0,
        });
    }
    let mut names = BTreeSet::new();
    let mut offset = 0;
    for (index, parameter) in raw.split('&').enumerate() {
        if index >= MAX_QUERY_PARAMETERS {
            return Err(QueryShapeError {
                reason: QueryShapeReason::TooMany,
                offset,
            });
        }
        let Some((name, _)) = parameter.split_once('=') else {
            return Err(QueryShapeError {
                reason: QueryShapeReason::Invalid,
                offset,
            });
        };
        if name.contains('%') || name != name.to_ascii_lowercase() {
            return Err(QueryShapeError {
                reason: QueryShapeReason::NoncanonicalName,
                offset,
            });
        }
        if !matches!(name, "version" | "list") {
            return Err(QueryShapeError {
                reason: QueryShapeReason::UnknownName,
                offset,
            });
        }
        if !names.insert(name) {
            return Err(QueryShapeError {
                reason: QueryShapeReason::Duplicate,
                offset,
            });
        }
        offset += parameter.len() + 1;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HygieneReason {
    BodyTooLarge,
    InvalidJson,
    DuplicateJsonKey,
    JsonTooDeep,
    TooManyJsonKeys,
    TooManyJsonValues,
    TooManyHeaders,
    HeaderBytesTooLarge,
    MultipleTokenHeaders,
    CombinedTokenHeader,
    InvalidTokenHeader,
    DuplicateQuery,
    NoncanonicalQuery,
    TooManyQueryParameters,
    InvalidQuery,
    ContentEncoding,
}

impl HygieneReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::BodyTooLarge => "body_too_large",
            Self::InvalidJson => "invalid_json",
            Self::DuplicateJsonKey => "duplicate_json_key",
            Self::JsonTooDeep => "json_too_deep",
            Self::TooManyJsonKeys => "too_many_json_keys",
            Self::TooManyJsonValues => "too_many_json_values",
            Self::TooManyHeaders => "too_many_headers",
            Self::HeaderBytesTooLarge => "header_bytes_too_large",
            Self::MultipleTokenHeaders => "multiple_token_headers",
            Self::CombinedTokenHeader => "combined_token_header",
            Self::InvalidTokenHeader => "invalid_token_header",
            Self::DuplicateQuery => "duplicate_query",
            Self::NoncanonicalQuery => "noncanonical_query",
            Self::TooManyQueryParameters => "too_many_query_parameters",
            Self::InvalidQuery => "invalid_query",
            Self::ContentEncoding => "content_encoding_not_supported",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HygieneError {
    reason: HygieneReason,
    offset: usize,
    input_digest: String,
}

impl HygieneError {
    fn new(reason: HygieneReason, offset: usize, bytes: &[u8], key: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(b"input-hygiene\0");
        hasher.update(bytes);
        Self {
            reason,
            offset,
            input_digest: hasher.finalize().to_hex()[..16].to_owned(),
        }
    }

    pub fn reason(&self) -> HygieneReason {
        self.reason
    }

    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Display for HygieneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "input_rejected reason={} offset={} input_digest={}",
            self.reason.as_str(),
            self.offset,
            self.input_digest
        )
    }
}

impl std::error::Error for HygieneError {}

#[derive(Clone)]
pub struct InputHygieneState {
    diagnostic_key: [u8; 32],
}

impl InputHygieneState {
    pub fn new(diagnostic_key: [u8; 32]) -> Self {
        Self { diagnostic_key }
    }
}

#[derive(Clone, Debug)]
pub struct StrictJsonBody(pub Value);

#[derive(Clone, Debug)]
pub struct ValidatedToken(pub Zeroizing<Vec<u8>>);

pub async fn input_hygiene_guard(
    State(state): State<InputHygieneState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    if parts
        .headers
        .contains_key(axum::http::header::CONTENT_ENCODING)
    {
        let error = HygieneError::new(
            HygieneReason::ContentEncoding,
            0,
            b"content-encoding",
            &state.diagnostic_key,
        );
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, error.to_string()).into_response();
    }
    let token = match validate_token_headers(&parts.headers, &state.diagnostic_key) {
        Ok(token) => token,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    if let Some(token) = token {
        parts.extensions.insert(ValidatedToken(token));
    }
    if let Err(shape) = validate_sensitive_query(parts.uri.query()) {
        let reason = match shape.reason {
            QueryShapeReason::Duplicate => HygieneReason::DuplicateQuery,
            QueryShapeReason::NoncanonicalName => HygieneReason::NoncanonicalQuery,
            QueryShapeReason::TooMany => HygieneReason::TooManyQueryParameters,
            QueryShapeReason::UnknownName | QueryShapeReason::Invalid => {
                HygieneReason::InvalidQuery
            }
        };
        let error = HygieneError::new(
            reason,
            shape.offset,
            parts
                .uri
                .path_and_query()
                .map_or(b"", |value| value.as_str().as_bytes()),
            &state.diagnostic_key,
        );
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    let bytes = match to_bytes(body, MAX_JSON_BODY_BYTES + 1).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let error = HygieneError::new(
                HygieneReason::BodyTooLarge,
                MAX_JSON_BODY_BYTES,
                b"bounded-body",
                &state.diagnostic_key,
            );
            return (StatusCode::PAYLOAD_TOO_LARGE, error.to_string()).into_response();
        }
    };
    if !bytes.is_empty() {
        let parsed = match parse_strict_json(&bytes, &state.diagnostic_key) {
            Ok(parsed) => parsed,
            Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
        parts.extensions.insert(StrictJsonBody(parsed));
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

pub fn validate_token_headers(
    headers: &HeaderMap,
    diagnostic_key: &[u8; 32],
) -> Result<Option<Zeroizing<Vec<u8>>>, HygieneError> {
    if headers.len() > MAX_HEADER_FIELDS {
        return Err(HygieneError::new(
            HygieneReason::TooManyHeaders,
            MAX_HEADER_FIELDS,
            b"header-inventory",
            diagnostic_key,
        ));
    }
    let bytes = headers.iter().fold(0_usize, |total, (name, value)| {
        total.saturating_add(name.as_str().len() + value.as_bytes().len())
    });
    if bytes > MAX_HEADER_BYTES {
        return Err(HygieneError::new(
            HygieneReason::HeaderBytesTooLarge,
            MAX_HEADER_BYTES,
            b"header-bytes",
            diagnostic_key,
        ));
    }
    let name = HeaderName::from_static("x-vault-token");
    let values: Vec<_> = headers.get_all(name).iter().collect();
    if values.len() > 1 {
        return Err(HygieneError::new(
            HygieneReason::MultipleTokenHeaders,
            1,
            b"x-vault-token",
            diagnostic_key,
        ));
    }
    let Some(value) = values.first() else {
        return Ok(None);
    };
    let bytes = value.as_bytes();
    if bytes.contains(&b',') {
        return Err(HygieneError::new(
            HygieneReason::CombinedTokenHeader,
            bytes.iter().position(|byte| *byte == b',').unwrap_or(0),
            b"x-vault-token",
            diagnostic_key,
        ));
    }
    if bytes.is_empty() || value.to_str().is_err() {
        return Err(HygieneError::new(
            HygieneReason::InvalidTokenHeader,
            0,
            b"x-vault-token",
            diagnostic_key,
        ));
    }
    Ok(Some(Zeroizing::new(bytes.to_vec())))
}

pub fn parse_strict_json(bytes: &[u8], diagnostic_key: &[u8; 32]) -> Result<Value, HygieneError> {
    if bytes.len() > MAX_JSON_BODY_BYTES {
        return Err(HygieneError::new(
            HygieneReason::BodyTooLarge,
            MAX_JSON_BODY_BYTES,
            bytes,
            diagnostic_key,
        ));
    }
    let state = Rc::new(ParseState::default());
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let result = ValueSeed {
        depth: 0,
        state: state.clone(),
    }
    .deserialize(&mut deserializer);
    let value = match result {
        Ok(value) => value,
        Err(error) => {
            let offset = error.column().saturating_sub(1);
            let rendered = error.to_string();
            let reason = if rendered.contains(DUPLICATE_KEY_MARKER) {
                HygieneReason::DuplicateJsonKey
            } else if rendered.contains(DEPTH_MARKER) {
                HygieneReason::JsonTooDeep
            } else if rendered.contains(KEY_LIMIT_MARKER) {
                HygieneReason::TooManyJsonKeys
            } else if rendered.contains(VALUE_LIMIT_MARKER) {
                HygieneReason::TooManyJsonValues
            } else {
                HygieneReason::InvalidJson
            };
            return Err(HygieneError::new(reason, offset, bytes, diagnostic_key));
        }
    };
    if let Err(error) = deserializer.end() {
        return Err(HygieneError::new(
            HygieneReason::InvalidJson,
            error.column().saturating_sub(1),
            bytes,
            diagnostic_key,
        ));
    }
    Ok(value)
}

#[derive(Default)]
struct ParseState {
    keys: Cell<usize>,
    values: Cell<usize>,
}

#[derive(Clone)]
struct ValueSeed {
    depth: usize,
    state: Rc<ParseState>,
}

impl<'de> DeserializeSeed<'de> for ValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(de::Error::custom(DEPTH_MARKER));
        }
        let values = self.state.values.get();
        if values >= MAX_JSON_VALUES {
            return Err(de::Error::custom(VALUE_LIMIT_MARKER));
        }
        self.state.values.set(values + 1);
        deserializer.deserialize_any(ValueVisitor(self))
    }
}

struct ValueVisitor(ValueSeed);

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid-json-number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.0.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(ValueSeed {
            depth: self.0.depth + 1,
            state: self.0.state.clone(),
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            let keys = self.0.state.keys.get();
            if keys >= MAX_JSON_KEYS {
                return Err(de::Error::custom(KEY_LIMIT_MARKER));
            }
            self.0.state.keys.set(keys + 1);
            if values.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_KEY_MARKER));
            }
            let value = object.next_value_seed(ValueSeed {
                depth: self.0.depth + 1,
                state: self.0.state.clone(),
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
