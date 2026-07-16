use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    Invalid,
    Limit,
    Truncated,
    Trailing,
    UnknownVersion,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "invalid canonical value",
            Self::Limit => "canonical value exceeds limit",
            Self::Truncated => "canonical value is truncated",
            Self::Trailing => "canonical value has trailing bytes",
            Self::UnknownVersion => "canonical value has unknown version",
        })
    }
}

impl std::error::Error for CodecError {}

pub trait Canonical: Sized {
    fn encode(&self) -> Result<Vec<u8>, CodecError>;
    fn decode(bytes: &[u8]) -> Result<Self, CodecError>;
}

pub struct Encoder(Vec<u8>);

impl Encoder {
    pub fn version(version: u8) -> Self {
        Self(vec![version])
    }

    pub fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub fn fixed(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    pub fn bytes(&mut self, value: &[u8], maximum: usize) -> Result<(), CodecError> {
        if value.len() > maximum || value.len() > u32::MAX as usize {
            return Err(CodecError::Limit);
        }
        self.u32(value.len() as u32);
        self.fixed(value);
        Ok(())
    }

    pub fn string(&mut self, value: &str, maximum: usize) -> Result<(), CodecError> {
        self.bytes(value.as_bytes(), maximum)
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    pub fn version(bytes: &'a [u8], expected: u8) -> Result<Self, CodecError> {
        let mut decoder = Self { bytes, cursor: 0 };
        if decoder.u8()? != expected {
            return Err(CodecError::UnknownVersion);
        }
        Ok(decoder)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self.cursor.checked_add(length).ok_or(CodecError::Limit)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(CodecError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }

    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool, CodecError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CodecError::Invalid),
        }
    }

    pub fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    pub fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, CodecError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(CodecError::Limit);
        }
        Ok(self.take(length)?.to_vec())
    }

    pub fn string(&mut self, maximum: usize) -> Result<String, CodecError> {
        String::from_utf8(self.bytes(maximum)?).map_err(|_| CodecError::Invalid)
    }

    pub fn finish(self) -> Result<(), CodecError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(CodecError::Trailing)
        }
    }
}
