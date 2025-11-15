//! RESP (`REdis` Serialization Protocol) parser and encoder
//!
//! Implements a subset of RESP protocol for AGQ communication.
//! Reference: <https://redis.io/docs/reference/protocol-spec/>

use crate::error::{Error, Result};
use bytes::{Buf, BytesMut};
use std::str;

/// Maximum size for a single RESP message (1MB)
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Maximum number of elements in an array
const MAX_ARRAY_SIZE: usize = 1024;

/// RESP value types
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::module_name_repetitions)]
pub enum RespValue {
    /// Simple string: +OK\r\n
    SimpleString(String),
    /// Error: -ERR message\r\n
    Error(String),
    /// Integer: :1000\r\n
    Integer(i64),
    /// Bulk string: $6\r\nfoobar\r\n
    BulkString(Vec<u8>),
    /// Array: *2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n
    Array(Vec<RespValue>),
    /// Null bulk string: $-1\r\n
    NullBulkString,
}

impl RespValue {
    /// Encode RESP value to bytes
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RespValue::SimpleString(s) => format!("+{s}\r\n").into_bytes(),
            RespValue::Error(s) => format!("-{s}\r\n").into_bytes(),
            RespValue::Integer(i) => format!(":{i}\r\n").into_bytes(),
            RespValue::BulkString(data) => {
                let mut result = format!("${}\r\n", data.len()).into_bytes();
                result.extend_from_slice(data);
                result.extend_from_slice(b"\r\n");
                result
            }
            RespValue::Array(items) => {
                let len = items.len();
                let mut result = format!("*{len}\r\n").into_bytes();
                for item in items {
                    result.extend_from_slice(&item.encode());
                }
                result
            }
            RespValue::NullBulkString => b"$-1\r\n".to_vec(),
        }
    }

    /// Extract bulk string as UTF-8 string
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not a bulk string or contains invalid UTF-8.
    pub fn as_string(&self) -> Result<String> {
        match self {
            RespValue::BulkString(data) => str::from_utf8(data)
                .map(std::string::ToString::to_string)
                .map_err(|_| Error::Protocol("Invalid UTF-8 in bulk string".to_string())),
            _ => Err(Error::Protocol("Expected bulk string".to_string())),
        }
    }
}

/// RESP protocol parser
#[allow(clippy::module_name_repetitions)]
pub struct RespParser {
    buffer: BytesMut,
}

impl RespParser {
    /// Create a new RESP parser
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(4096),
        }
    }

    /// Add data to the parser buffer
    ///
    /// # Security
    /// Enforces maximum message size to prevent `DoS` attacks
    ///
    /// # Errors
    ///
    /// Returns an error if the message would exceed the maximum size limit.
    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        if self.buffer.len() + data.len() > MAX_MESSAGE_SIZE {
            return Err(Error::MessageTooLarge);
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// Try to parse a complete RESP value from the buffer
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer contains invalid RESP data.
    ///
    /// # Panics
    ///
    /// Panics if the cursor position overflows, which should never happen in practice.
    pub fn parse(&mut self) -> Result<Option<RespValue>> {
        if self.buffer.is_empty() {
            return Ok(None);
        }

        let mut cursor = std::io::Cursor::new(&self.buffer[..]);
        match self.parse_value(&mut cursor) {
            Ok(value) => {
                let pos = usize::try_from(cursor.position()).expect("position overflow");
                self.buffer.advance(pos);
                Ok(Some(value))
            }
            Err(Error::Protocol(_)) if self.buffer.len() < MAX_MESSAGE_SIZE => {
                // Incomplete message, wait for more data
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Parse a RESP value from cursor
    fn parse_value<R: std::io::Read>(&self, cursor: &mut R) -> Result<RespValue> {
        let mut type_byte = [0u8; 1];
        cursor
            .read_exact(&mut type_byte)
            .map_err(|_| Error::Protocol("Incomplete message".to_string()))?;

        match type_byte[0] {
            b'+' => self.parse_simple_string(cursor),
            b'-' => self.parse_error(cursor),
            b':' => self.parse_integer(cursor),
            b'$' => self.parse_bulk_string(cursor),
            b'*' => self.parse_array(cursor),
            _ => Err(Error::Protocol(format!(
                "Unknown RESP type: {}",
                type_byte[0]
            ))),
        }
    }

    /// Parse simple string: +OK\r\n
    #[allow(clippy::unused_self)]
    fn parse_simple_string<R: std::io::Read>(&self, cursor: &mut R) -> Result<RespValue> {
        let line = Self::read_line(cursor)?;
        Ok(RespValue::SimpleString(line))
    }

    /// Parse error: -ERR message\r\n
    #[allow(clippy::unused_self)]
    fn parse_error<R: std::io::Read>(&self, cursor: &mut R) -> Result<RespValue> {
        let line = Self::read_line(cursor)?;
        Ok(RespValue::Error(line))
    }

    /// Parse integer: :1000\r\n
    #[allow(clippy::unused_self)]
    fn parse_integer<R: std::io::Read>(&self, cursor: &mut R) -> Result<RespValue> {
        let line = Self::read_line(cursor)?;
        let num = line
            .parse::<i64>()
            .map_err(|_| Error::Protocol("Invalid integer".to_string()))?;
        Ok(RespValue::Integer(num))
    }

    /// Parse bulk string: $6\r\nfoobar\r\n
    ///
    /// # Security
    /// Validates size before allocating to prevent `DoS`
    #[allow(clippy::unused_self)]
    fn parse_bulk_string<R: std::io::Read>(&self, cursor: &mut R) -> Result<RespValue> {
        let size_line = Self::read_line(cursor)?;
        let size = size_line
            .parse::<i64>()
            .map_err(|_| Error::Protocol("Invalid bulk string size".to_string()))?;

        if size == -1 {
            return Ok(RespValue::NullBulkString);
        }

        if size < 0 {
            return Err(Error::Protocol("Invalid bulk string size".to_string()));
        }

        // Security: Check size limit before allocating
        let size = usize::try_from(size)
            .map_err(|_| Error::Protocol("Invalid bulk string size".to_string()))?;
        if size > MAX_MESSAGE_SIZE {
            return Err(Error::MessageTooLarge);
        }

        let mut data = vec![0u8; size];
        cursor
            .read_exact(&mut data)
            .map_err(|_| Error::Protocol("Incomplete bulk string".to_string()))?;

        let mut crlf = [0u8; 2];
        cursor
            .read_exact(&mut crlf)
            .map_err(|_| Error::Protocol("Missing CRLF after bulk string".to_string()))?;

        if crlf != [b'\r', b'\n'] {
            return Err(Error::Protocol("Invalid CRLF".to_string()));
        }

        Ok(RespValue::BulkString(data))
    }

    /// Parse array: *2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n
    ///
    /// # Security
    /// Validates array size to prevent `DoS` via deeply nested structures
    fn parse_array<R: std::io::Read>(&self, cursor: &mut R) -> Result<RespValue> {
        let size_line = Self::read_line(cursor)?;
        let size = size_line
            .parse::<i64>()
            .map_err(|_| Error::Protocol("Invalid array size".to_string()))?;

        if size < 0 {
            return Err(Error::Protocol("Invalid array size".to_string()));
        }

        // Security: Limit array size to prevent DoS
        let size =
            usize::try_from(size).map_err(|_| Error::Protocol("Invalid array size".to_string()))?;
        if size > MAX_ARRAY_SIZE {
            return Err(Error::Protocol(format!(
                "Array size {size} exceeds maximum {MAX_ARRAY_SIZE}"
            )));
        }

        let mut items = Vec::with_capacity(size);
        for _ in 0..size {
            items.push(self.parse_value(cursor)?);
        }

        Ok(RespValue::Array(items))
    }

    /// Read a line until \r\n
    fn read_line(cursor: &mut dyn std::io::Read) -> Result<String> {
        let mut line = Vec::new();
        let mut last_byte = 0u8;

        loop {
            let mut byte = [0u8; 1];
            cursor
                .read_exact(&mut byte)
                .map_err(|_| Error::Protocol("Incomplete line".to_string()))?;

            if byte[0] == b'\n' && last_byte == b'\r' {
                line.pop(); // Remove \r
                break;
            }

            line.push(byte[0]);
            last_byte = byte[0];

            // Security: Prevent infinite line reads
            if line.len() > MAX_MESSAGE_SIZE {
                return Err(Error::MessageTooLarge);
            }
        }

        str::from_utf8(&line)
            .map(std::string::ToString::to_string)
            .map_err(|_| Error::Protocol("Invalid UTF-8 in line".to_string()))
    }
}

impl Default for RespParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_simple_string() {
        let value = RespValue::SimpleString("OK".to_string());
        assert_eq!(value.encode(), b"+OK\r\n");
    }

    #[test]
    fn test_encode_error() {
        let value = RespValue::Error("ERR message".to_string());
        assert_eq!(value.encode(), b"-ERR message\r\n");
    }

    #[test]
    fn test_encode_integer() {
        let value = RespValue::Integer(1000);
        assert_eq!(value.encode(), b":1000\r\n");
    }

    #[test]
    fn test_encode_bulk_string() {
        let value = RespValue::BulkString(b"foobar".to_vec());
        assert_eq!(value.encode(), b"$6\r\nfoobar\r\n");
    }

    #[test]
    fn test_encode_array() {
        let value = RespValue::Array(vec![
            RespValue::BulkString(b"foo".to_vec()),
            RespValue::BulkString(b"bar".to_vec()),
        ]);
        assert_eq!(value.encode(), b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n");
    }

    #[test]
    fn test_parse_simple_string() {
        let mut parser = RespParser::new();
        parser.feed(b"+OK\r\n").unwrap();
        let value = parser.parse().unwrap().unwrap();
        assert_eq!(value, RespValue::SimpleString("OK".to_string()));
    }

    #[test]
    fn test_parse_bulk_string() {
        let mut parser = RespParser::new();
        parser.feed(b"$6\r\nfoobar\r\n").unwrap();
        let value = parser.parse().unwrap().unwrap();
        assert_eq!(value, RespValue::BulkString(b"foobar".to_vec()));
    }

    #[test]
    fn test_parse_array() {
        let mut parser = RespParser::new();
        parser.feed(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n").unwrap();
        let value = parser.parse().unwrap().unwrap();
        assert_eq!(
            value,
            RespValue::Array(vec![
                RespValue::BulkString(b"foo".to_vec()),
                RespValue::BulkString(b"bar".to_vec()),
            ])
        );
    }

    #[test]
    fn test_parse_incomplete_message() {
        let mut parser = RespParser::new();
        parser.feed(b"*2\r\n$3\r\nfoo").unwrap();
        let value = parser.parse().unwrap();
        assert!(value.is_none(), "Should wait for complete message");
    }

    #[test]
    fn test_message_size_limit() {
        let mut parser = RespParser::new();
        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let result = parser.feed(&oversized);
        assert!(matches!(result, Err(Error::MessageTooLarge)));
    }

    #[test]
    fn test_bulk_string_size_validation() {
        let mut parser = RespParser::new();
        let oversized_bulk = format!("${}\r\n", MAX_MESSAGE_SIZE + 1);
        parser.feed(oversized_bulk.as_bytes()).unwrap();
        let result = parser.parse();
        assert!(matches!(result, Err(Error::MessageTooLarge)));
    }

    #[test]
    fn test_null_bulk_string() {
        let mut parser = RespParser::new();
        parser.feed(b"$-1\r\n").unwrap();
        let value = parser.parse().unwrap().unwrap();
        assert_eq!(value, RespValue::NullBulkString);
    }

    #[test]
    fn test_as_string_conversion() {
        let value = RespValue::BulkString(b"hello".to_vec());
        assert_eq!(value.as_string().unwrap(), "hello");
    }
}
