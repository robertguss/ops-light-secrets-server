//! Raw request-target validation and the sole canonical resource parser.
//!
//! The evidence-backed segment alphabet is ASCII alphanumeric plus `-._~+`,
//! with space and non-ASCII UTF-8 bytes represented by uppercase percent
//! escapes. Escaped unreserved bytes, separators, backslashes, percent signs,
//! lowercase escapes, raw non-ASCII, and Unicode normalization are forbidden.

use std::collections::BTreeSet;
use std::fmt;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

pub const MAX_RAW_TARGET_BYTES: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resource {
    pub mount: String,
    pub canonical_segments: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointKind {
    Data,
    Metadata,
    List,
    Delete,
    Undelete,
    Destroy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRequest {
    pub kind: EndpointKind,
    pub resource: Resource,
    pub version: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseReason {
    TargetTooLong,
    InvalidEndpoint,
    MissingResource,
    EmptySegment,
    DotSegment,
    MalformedEscape,
    EncodedSeparator,
    EncodedPercent,
    NoncanonicalEncoding,
    InvalidUtf8,
    ControlCharacter,
    UnsupportedCharacter,
    DuplicateQuery,
    NoncanonicalQuery,
    InvalidQuery,
}

impl ParseReason {
    fn code(self) -> &'static str {
        match self {
            Self::TargetTooLong => "target_too_long",
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::MissingResource => "missing_resource",
            Self::EmptySegment => "empty_segment",
            Self::DotSegment => "dot_segment",
            Self::MalformedEscape => "malformed_escape",
            Self::EncodedSeparator => "encoded_separator",
            Self::EncodedPercent => "encoded_percent",
            Self::NoncanonicalEncoding => "noncanonical_encoding",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::ControlCharacter => "control_character",
            Self::UnsupportedCharacter => "unsupported_character",
            Self::DuplicateQuery => "duplicate_query",
            Self::NoncanonicalQuery => "noncanonical_query",
            Self::InvalidQuery => "invalid_query",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError {
    reason: ParseReason,
    offset: usize,
    target_digest: String,
}

impl ParseError {
    pub fn reason(&self) -> ParseReason {
        self.reason
    }

    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "raw_target_rejected reason={} offset={} target_digest={}",
            self.reason.code(),
            self.offset,
            self.target_digest
        )
    }
}

impl std::error::Error for ParseError {}

pub fn parse_raw_target(method: &Method, raw_target: &str) -> Result<EndpointRequest, ParseError> {
    if raw_target.len() > MAX_RAW_TARGET_BYTES {
        return Err(error(
            ParseReason::TargetTooLong,
            MAX_RAW_TARGET_BYTES,
            raw_target,
        ));
    }
    if raw_target.is_empty() {
        return Err(error(ParseReason::InvalidEndpoint, 0, raw_target));
    }
    let (raw_path, raw_query) = raw_target
        .split_once('?')
        .map_or((raw_target, None), |(path, query)| (path, Some(query)));
    let query = parse_query(
        raw_query,
        raw_path.len() + usize::from(raw_query.is_some()),
        raw_target,
    )?;

    let raw_segments: Vec<&str> = raw_path.split('/').collect();
    if raw_segments.len() < 4 || !raw_segments[0].is_empty() || raw_segments[1] != "v1" {
        return Err(error(ParseReason::InvalidEndpoint, 0, raw_target));
    }
    let mount_offset = "/v1/".len();
    let mount = decode_segment(raw_segments[2], mount_offset, raw_target)?;
    if mount.is_empty() {
        return Err(error(
            ParseReason::InvalidEndpoint,
            mount_offset,
            raw_target,
        ));
    }
    let form = raw_segments[3];
    let list_method = method.as_str() == "LIST";
    let list_intent = list_method || query.list;
    if list_intent && form != "metadata" {
        return Err(error(ParseReason::InvalidQuery, raw_path.len(), raw_target));
    }
    if query.list && method != Method::GET && !list_method {
        return Err(error(ParseReason::InvalidQuery, raw_path.len(), raw_target));
    }
    let kind = match (form, list_intent) {
        ("data", false) => EndpointKind::Data,
        ("metadata", false) => EndpointKind::Metadata,
        ("metadata", true) => EndpointKind::List,
        ("delete", false) => EndpointKind::Delete,
        ("undelete", false) => EndpointKind::Undelete,
        ("destroy", false) => EndpointKind::Destroy,
        _ => {
            return Err(error(
                ParseReason::InvalidEndpoint,
                mount_offset,
                raw_target,
            ));
        }
    };
    if query.version.is_some() && kind != EndpointKind::Data {
        return Err(error(ParseReason::InvalidQuery, raw_path.len(), raw_target));
    }

    let resource_start = raw_segments[..4]
        .iter()
        .map(|value| value.len() + 1)
        .sum::<usize>();
    let mut resource_raw = raw_segments[4..].to_vec();
    if resource_raw.last() == Some(&"") {
        if kind == EndpointKind::List {
            resource_raw.pop();
        } else {
            return Err(error(
                ParseReason::EmptySegment,
                raw_path.len() - 1,
                raw_target,
            ));
        }
    }
    if resource_raw.is_empty() && kind != EndpointKind::List {
        return Err(error(
            ParseReason::MissingResource,
            raw_path.len(),
            raw_target,
        ));
    }

    let mut canonical_segments = Vec::with_capacity(resource_raw.len());
    let mut offset = resource_start;
    for segment in resource_raw {
        if segment.is_empty() {
            return Err(error(ParseReason::EmptySegment, offset, raw_target));
        }
        canonical_segments.push(decode_segment(segment, offset, raw_target)?);
        offset += segment.len() + 1;
    }
    Ok(EndpointRequest {
        kind,
        resource: Resource {
            mount,
            canonical_segments,
        },
        version: query.version,
    })
}

pub async fn raw_target_guard(mut request: Request<Body>, next: Next) -> Response {
    let raw_target = request
        .uri()
        .path_and_query()
        .map_or(request.uri().path(), |value| value.as_str());
    match parse_raw_target(request.method(), raw_target) {
        Ok(endpoint) => {
            request.extensions_mut().insert(endpoint);
            next.run(request).await
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

struct Query {
    version: Option<u64>,
    list: bool,
}

fn parse_query(raw: Option<&str>, offset: usize, target: &str) -> Result<Query, ParseError> {
    let mut version = None;
    let mut list = false;
    let mut names = BTreeSet::new();
    let Some(raw) = raw else {
        return Ok(Query { version, list });
    };
    if raw.is_empty() {
        return Err(error(ParseReason::InvalidQuery, offset, target));
    }
    let mut parameter_offset = offset;
    for parameter in raw.split('&') {
        let Some((name, value)) = parameter.split_once('=') else {
            return Err(error(ParseReason::InvalidQuery, parameter_offset, target));
        };
        if name.contains('%') || name != name.to_ascii_lowercase() {
            return Err(error(
                ParseReason::NoncanonicalQuery,
                parameter_offset,
                target,
            ));
        }
        if !names.insert(name) {
            return Err(error(ParseReason::DuplicateQuery, parameter_offset, target));
        }
        match name {
            "version" => {
                if value.is_empty()
                    || value.starts_with('0')
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(error(ParseReason::InvalidQuery, parameter_offset, target));
                }
                version = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| error(ParseReason::InvalidQuery, parameter_offset, target))?,
                );
            }
            "list" if value == "true" => list = true,
            "list" => return Err(error(ParseReason::InvalidQuery, parameter_offset, target)),
            _ => return Err(error(ParseReason::InvalidQuery, parameter_offset, target)),
        }
        parameter_offset += parameter.len() + 1;
    }
    Ok(Query { version, list })
}

fn decode_segment(raw: &str, base_offset: usize, target: &str) -> Result<String, ParseError> {
    if raw.is_empty() {
        return Err(error(ParseReason::EmptySegment, base_offset, target));
    }
    if !raw.is_ascii() {
        return Err(error(
            ParseReason::NoncanonicalEncoding,
            base_offset,
            target,
        ));
    }
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len() {
                return Err(error(
                    ParseReason::MalformedEscape,
                    base_offset + index,
                    target,
                ));
            }
            let high = uppercase_hex(bytes[index + 1]);
            let low = uppercase_hex(bytes[index + 2]);
            let (Some(high), Some(low)) = (high, low) else {
                return Err(error(
                    if bytes[index + 1].is_ascii_hexdigit() && bytes[index + 2].is_ascii_hexdigit()
                    {
                        ParseReason::NoncanonicalEncoding
                    } else {
                        ParseReason::MalformedEscape
                    },
                    base_offset + index,
                    target,
                ));
            };
            let value = high * 16 + low;
            match value {
                b'/' | b'\\' => {
                    return Err(error(
                        ParseReason::EncodedSeparator,
                        base_offset + index,
                        target,
                    ));
                }
                b'%' => {
                    return Err(error(
                        ParseReason::EncodedPercent,
                        base_offset + index,
                        target,
                    ));
                }
                0..=0x1f | 0x7f => {
                    return Err(error(
                        ParseReason::ControlCharacter,
                        base_offset + index,
                        target,
                    ));
                }
                b'.' | b'+' | b'-' | b'_' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => {
                    return Err(error(
                        ParseReason::NoncanonicalEncoding,
                        base_offset + index,
                        target,
                    ));
                }
                _ => decoded.push(value),
            }
            index += 3;
            continue;
        }
        if byte == b'\\' || byte.is_ascii_control() || byte == b' ' {
            return Err(error(
                if byte.is_ascii_control() {
                    ParseReason::ControlCharacter
                } else {
                    ParseReason::UnsupportedCharacter
                },
                base_offset + index,
                target,
            ));
        }
        if !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.' | b'~' | b'+') {
            return Err(error(
                ParseReason::UnsupportedCharacter,
                base_offset + index,
                target,
            ));
        }
        decoded.push(byte);
        index += 1;
    }
    let decoded = String::from_utf8(decoded)
        .map_err(|_| error(ParseReason::InvalidUtf8, base_offset, target))?;
    if decoded == "." || decoded == ".." {
        return Err(error(ParseReason::DotSegment, base_offset, target));
    }
    Ok(decoded)
}

fn uppercase_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn error(reason: ParseReason, offset: usize, target: &str) -> ParseError {
    ParseError {
        reason,
        offset,
        target_digest: blake3::hash(target.as_bytes()).to_hex()[..16].to_owned(),
    }
}
