//! Error types for AGQ

use thiserror::Error;

/// Result type alias for AGQ operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in AGQ operations
#[derive(Error, Debug)]
pub enum Error {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// RESP protocol parsing error
    #[error("RESP protocol error: {0}")]
    Protocol(String),

    /// Authentication error
    #[error("Authentication required")]
    NoAuth,

    /// Invalid command
    #[error("Unknown command: {0}")]
    UnknownCommand(String),

    /// Invalid arguments
    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),

    /// Message too large
    #[error("Message exceeds maximum size limit")]
    MessageTooLarge,

    /// Connection closed
    #[error("Connection closed")]
    ConnectionClosed,

    /// Timeout
    #[error("Operation timeout")]
    Timeout,
}

impl Error {
    /// Convert error to RESP error message
    #[must_use]
    pub fn to_resp_error(&self) -> String {
        match self {
            Error::NoAuth => "-ERR NOAUTH Authentication required\r\n".to_string(),
            Error::UnknownCommand(cmd) => format!("-ERR unknown command '{cmd}'\r\n"),
            Error::InvalidArguments(msg) => format!("-ERR {msg}\r\n"),
            Error::Protocol(msg) => format!("-ERR Protocol error: {msg}\r\n"),
            Error::MessageTooLarge => "-ERR Message too large\r\n".to_string(),
            _ => "-ERR Internal error\r\n".to_string(),
        }
    }
}
