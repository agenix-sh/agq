//! TCP server implementation with RESP protocol support

use crate::error::{Error, Result};
use crate::resp::{RespParser, RespValue};
use crate::storage::{Database, StringOps};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent connections
const MAX_CONNECTIONS: usize = 1000;

/// Read timeout for client connections
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// AGQ Server
pub struct Server {
    listener: TcpListener,
    /// Session key for authentication (in Phase 1, single static key)
    /// In production, this would be per-session with rotation
    session_key: Arc<Vec<u8>>,
    /// Database for persistent storage
    db: Arc<Database>,
}

impl Server {
    /// Create a new server bound to the given address
    ///
    /// # Arguments
    /// * `addr` - Address to bind to (e.g., "127.0.0.1:6379")
    /// * `session_key` - Authentication key for clients
    /// * `db` - Database instance for persistent storage
    ///
    /// # Errors
    ///
    /// Returns an error if binding to the address fails.
    pub async fn new(addr: &str, session_key: Vec<u8>, db: Database) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!("AGQ server listening on {}", addr);

        Ok(Self {
            listener,
            session_key: Arc::new(session_key),
            db: Arc::new(db),
        })
    }

    /// Run the server, accepting connections
    ///
    /// # Errors
    ///
    /// Returns an error if a client connection fails.
    pub async fn run(self) -> Result<()> {
        let mut connection_count = 0usize;

        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    // Security: Limit concurrent connections
                    if connection_count >= MAX_CONNECTIONS {
                        warn!(
                            "Connection limit reached, rejecting connection from {}",
                            addr
                        );
                        drop(stream);
                        continue;
                    }

                    connection_count += 1;
                    debug!(
                        "Accepted connection from {}, total: {}",
                        addr, connection_count
                    );

                    let session_key = Arc::clone(&self.session_key);
                    let db = Arc::clone(&self.db);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, session_key, db).await {
                            debug!("Connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Get the local address the server is bound to
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be retrieved.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.listener.local_addr().map_err(Error::from)
    }
}

/// Handle a single client connection
async fn handle_connection(
    mut stream: TcpStream,
    session_key: Arc<Vec<u8>>,
    db: Arc<Database>,
) -> Result<()> {
    let mut parser = RespParser::new();
    let mut authenticated = false;
    let mut buffer = vec![0u8; 4096];

    loop {
        // Security: Timeout all reads to prevent slowloris attacks
        let read_result = timeout(READ_TIMEOUT, stream.read(&mut buffer)).await;

        let n = match read_result {
            Ok(Ok(0)) => {
                debug!("Client disconnected");
                return Ok(());
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                return Err(Error::from(e));
            }
            Err(_) => {
                warn!("Read timeout");
                return Err(Error::Timeout);
            }
        };

        // Feed data to parser
        parser.feed(&buffer[..n])?;

        // Process all complete messages
        while let Some(value) = parser.parse()? {
            match handle_command(value, &mut authenticated, &session_key, &db) {
                Ok(response) => {
                    stream.write_all(&response.encode()).await?;
                }
                Err(e) => {
                    let error_msg = e.to_resp_error();
                    stream.write_all(error_msg.as_bytes()).await?;
                }
            }
        }
    }
}

/// Handle a single RESP command
///
/// # Security
/// - Validates authentication state before executing commands
/// - Uses constant-time comparison for session keys
fn handle_command(
    value: RespValue,
    authenticated: &mut bool,
    session_key: &[u8],
    db: &Database,
) -> Result<RespValue> {
    let args = match value {
        RespValue::Array(args) if !args.is_empty() => args,
        _ => {
            return Err(Error::Protocol(
                "Expected array with at least one element".to_string(),
            ))
        }
    };

    let command = args[0].as_string()?.to_uppercase();

    match command.as_str() {
        "AUTH" => handle_auth(&args, authenticated, session_key),
        "PING" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_ping(&args)
        }
        "GET" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_get(&args, db)
        }
        "SET" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_set(&args, db)
        }
        "DEL" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_del(&args, db)
        }
        "EXISTS" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_exists(&args, db)
        }
        _ => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            Err(Error::UnknownCommand(command))
        }
    }
}

/// Handle AUTH command
///
/// # Security
/// - Uses constant-time comparison to prevent timing attacks
/// - Validates key is not empty
/// - Requires exactly one argument
fn handle_auth(
    args: &[RespValue],
    authenticated: &mut bool,
    expected_key: &[u8],
) -> Result<RespValue> {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "AUTH requires exactly one argument".to_string(),
        ));
    }

    let RespValue::BulkString(provided_key) = &args[1] else {
        return Err(Error::InvalidArguments(
            "AUTH key must be a bulk string".to_string(),
        ));
    };

    // Security: Reject empty keys
    if provided_key.is_empty() {
        return Err(Error::InvalidArguments(
            "AUTH key cannot be empty".to_string(),
        ));
    }

    // Security: Constant-time comparison to prevent timing attacks
    // Pad to same length for constant-time comparison
    let max_len = provided_key.len().max(expected_key.len());
    let mut provided_padded = provided_key.clone();
    let mut expected_padded = expected_key.to_vec();

    provided_padded.resize(max_len, 0);
    expected_padded.resize(max_len, 0);

    let keys_match = provided_padded.ct_eq(&expected_padded);

    if keys_match.into() {
        *authenticated = true;
        info!("Client authenticated successfully");
        Ok(RespValue::SimpleString("OK".to_string()))
    } else {
        warn!("Authentication failed: invalid key");
        Err(Error::InvalidArguments(
            "Invalid authentication key".to_string(),
        ))
    }
}

/// Handle PING command
///
/// Supports both:
/// - PING -> +PONG
/// - PING message -> $7\r\nmessage\r\n (echo)
fn handle_ping(args: &[RespValue]) -> Result<RespValue> {
    match args.len() {
        1 => {
            // Simple PING
            Ok(RespValue::SimpleString("PONG".to_string()))
        }
        2 => {
            // PING with message - echo it back
            match &args[1] {
                RespValue::BulkString(msg) => Ok(RespValue::BulkString(msg.clone())),
                _ => Err(Error::InvalidArguments(
                    "PING message must be a bulk string".to_string(),
                )),
            }
        }
        _ => Err(Error::InvalidArguments(
            "PING accepts 0 or 1 arguments".to_string(),
        )),
    }
}

/// Handle GET command
///
/// Syntax: GET key
/// Returns: Bulk string value or nil if key doesn't exist
fn handle_get(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "GET requires exactly one argument".to_string(),
        ));
    }

    let key = args[1].as_string()?;

    match db.get(&key)? {
        Some(value) => Ok(RespValue::BulkString(value)),
        None => Ok(RespValue::NullBulkString),
    }
}

/// Handle SET command
///
/// Syntax: SET key value
/// Returns: OK
fn handle_set(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 3 {
        return Err(Error::InvalidArguments(
            "SET requires exactly two arguments".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let RespValue::BulkString(value) = &args[2] else {
        return Err(Error::InvalidArguments(
            "SET value must be a bulk string".to_string(),
        ));
    };

    db.set(&key, value)?;
    Ok(RespValue::SimpleString("OK".to_string()))
}

/// Handle DEL command
///
/// Syntax: DEL key
/// Returns: Integer - 1 if key was deleted, 0 if key didn't exist
fn handle_del(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "DEL requires exactly one argument".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let deleted = db.del(&key)?;

    Ok(RespValue::Integer(i64::from(deleted)))
}

/// Handle EXISTS command
///
/// Syntax: EXISTS key
/// Returns: Integer - 1 if key exists, 0 if it doesn't
fn handle_exists(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "EXISTS requires exactly one argument".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let exists = db.exists(&key)?;

    Ok(RespValue::Integer(i64::from(exists)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_db() -> (Database, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let db = Database::open(&db_path).unwrap();
        (db, temp_dir)
    }

    #[tokio::test]
    async fn test_auth_handler_success() {
        let mut authenticated = false;
        let session_key = b"test_key".to_vec();

        let args = vec![
            RespValue::BulkString(b"AUTH".to_vec()),
            RespValue::BulkString(b"test_key".to_vec()),
        ];

        let result = handle_auth(&args, &mut authenticated, &session_key).unwrap();

        assert_eq!(result, RespValue::SimpleString("OK".to_string()));
        assert!(authenticated);
    }

    #[tokio::test]
    async fn test_auth_handler_wrong_key() {
        let mut authenticated = false;
        let session_key = b"correct_key".to_vec();

        let args = vec![
            RespValue::BulkString(b"AUTH".to_vec()),
            RespValue::BulkString(b"wrong_key".to_vec()),
        ];

        let result = handle_auth(&args, &mut authenticated, &session_key);

        assert!(result.is_err());
        assert!(!authenticated);
    }

    #[tokio::test]
    async fn test_auth_handler_empty_key() {
        let mut authenticated = false;
        let session_key = b"test_key".to_vec();

        let args = vec![
            RespValue::BulkString(b"AUTH".to_vec()),
            RespValue::BulkString(b"".to_vec()),
        ];

        let result = handle_auth(&args, &mut authenticated, &session_key);

        assert!(result.is_err());
        assert!(!authenticated);
    }

    #[tokio::test]
    async fn test_auth_handler_missing_argument() {
        let mut authenticated = false;
        let session_key = b"test_key".to_vec();

        let args = vec![RespValue::BulkString(b"AUTH".to_vec())];

        let result = handle_auth(&args, &mut authenticated, &session_key);

        assert!(result.is_err());
        assert!(!authenticated);
    }

    #[tokio::test]
    async fn test_ping_handler_simple() {
        let args = vec![RespValue::BulkString(b"PING".to_vec())];

        let result = handle_ping(&args).unwrap();

        assert_eq!(result, RespValue::SimpleString("PONG".to_string()));
    }

    #[tokio::test]
    async fn test_ping_handler_with_message() {
        let args = vec![
            RespValue::BulkString(b"PING".to_vec()),
            RespValue::BulkString(b"hello".to_vec()),
        ];

        let result = handle_ping(&args).unwrap();

        assert_eq!(result, RespValue::BulkString(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn test_ping_handler_too_many_args() {
        let args = vec![
            RespValue::BulkString(b"PING".to_vec()),
            RespValue::BulkString(b"arg1".to_vec()),
            RespValue::BulkString(b"arg2".to_vec()),
        ];

        let result = handle_ping(&args);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_command_requires_auth() {
        let mut authenticated = false;
        let session_key = b"test_key".to_vec();
        let (db, _temp) = test_db();

        let args = vec![RespValue::BulkString(b"PING".to_vec())];
        let value = RespValue::Array(args);

        let result = handle_command(value, &mut authenticated, &session_key, &db);

        assert!(matches!(result, Err(Error::NoAuth)));
    }

    #[tokio::test]
    async fn test_unknown_command() {
        let mut authenticated = true;
        let session_key = b"test_key".to_vec();
        let (db, _temp) = test_db();

        let args = vec![RespValue::BulkString(b"UNKNOWN".to_vec())];
        let value = RespValue::Array(args);

        let result = handle_command(value, &mut authenticated, &session_key, &db);

        assert!(matches!(result, Err(Error::UnknownCommand(_))));
    }

    #[tokio::test]
    async fn test_constant_time_comparison() {
        use std::time::Instant;

        let mut authenticated = false;
        let session_key = b"a".repeat(32);

        // Warm up to avoid cold start timing differences
        for _ in 0..100 {
            let args = vec![
                RespValue::BulkString(b"AUTH".to_vec()),
                RespValue::BulkString(session_key.clone()),
            ];
            let _ = handle_auth(&args, &mut authenticated, &session_key);
        }

        // Test 1: Matching keys (averaged over multiple runs)
        let mut total_match = std::time::Duration::ZERO;
        for _ in 0..1000 {
            authenticated = false;
            let args = vec![
                RespValue::BulkString(b"AUTH".to_vec()),
                RespValue::BulkString(session_key.clone()),
            ];
            let start = Instant::now();
            let _ = handle_auth(&args, &mut authenticated, &session_key);
            total_match += start.elapsed();
        }

        // Test 2: Non-matching keys (averaged over multiple runs)
        let wrong_key = {
            let mut key = session_key.clone();
            key[0] = b'b';
            key
        };

        let mut total_no_match = std::time::Duration::ZERO;
        for _ in 0..1000 {
            authenticated = false;
            let args = vec![
                RespValue::BulkString(b"AUTH".to_vec()),
                RespValue::BulkString(wrong_key.clone()),
            ];
            let start = Instant::now();
            let _ = handle_auth(&args, &mut authenticated, &session_key);
            total_no_match += start.elapsed();
        }

        let avg_match = total_match.as_nanos() / 1000;
        let avg_no_match = total_no_match.as_nanos() / 1000;

        // Timing should be similar (within 50% variance due to system noise)
        #[allow(clippy::cast_precision_loss)]
        let ratio = avg_match as f64 / avg_no_match as f64;
        assert!(
            (0.5..=2.0).contains(&ratio),
            "Timing difference too large: avg {avg_match} ns vs avg {avg_no_match} ns (ratio: {ratio})"
        );
    }

    #[tokio::test]
    async fn test_get_handler_nonexistent() {
        let (db, _temp) = test_db();

        let args = vec![
            RespValue::BulkString(b"GET".to_vec()),
            RespValue::BulkString(b"nonexistent".to_vec()),
        ];

        let result = handle_get(&args, &db).unwrap();
        assert_eq!(result, RespValue::NullBulkString);
    }

    #[tokio::test]
    async fn test_set_and_get_handlers() {
        let (db, _temp) = test_db();

        // SET key value
        let set_args = vec![
            RespValue::BulkString(b"SET".to_vec()),
            RespValue::BulkString(b"mykey".to_vec()),
            RespValue::BulkString(b"myvalue".to_vec()),
        ];

        let result = handle_set(&set_args, &db).unwrap();
        assert_eq!(result, RespValue::SimpleString("OK".to_string()));

        // GET key
        let get_args = vec![
            RespValue::BulkString(b"GET".to_vec()),
            RespValue::BulkString(b"mykey".to_vec()),
        ];

        let result = handle_get(&get_args, &db).unwrap();
        assert_eq!(result, RespValue::BulkString(b"myvalue".to_vec()));
    }

    #[tokio::test]
    async fn test_del_handler() {
        let (db, _temp) = test_db();

        // SET key first
        let set_args = vec![
            RespValue::BulkString(b"SET".to_vec()),
            RespValue::BulkString(b"mykey".to_vec()),
            RespValue::BulkString(b"myvalue".to_vec()),
        ];
        handle_set(&set_args, &db).unwrap();

        // DEL key
        let del_args = vec![
            RespValue::BulkString(b"DEL".to_vec()),
            RespValue::BulkString(b"mykey".to_vec()),
        ];

        let result = handle_del(&del_args, &db).unwrap();
        assert_eq!(result, RespValue::Integer(1));

        // DEL nonexistent key
        let result = handle_del(&del_args, &db).unwrap();
        assert_eq!(result, RespValue::Integer(0));
    }

    #[tokio::test]
    async fn test_exists_handler() {
        let (db, _temp) = test_db();

        // EXISTS on nonexistent key
        let exists_args = vec![
            RespValue::BulkString(b"EXISTS".to_vec()),
            RespValue::BulkString(b"mykey".to_vec()),
        ];

        let result = handle_exists(&exists_args, &db).unwrap();
        assert_eq!(result, RespValue::Integer(0));

        // SET key
        let set_args = vec![
            RespValue::BulkString(b"SET".to_vec()),
            RespValue::BulkString(b"mykey".to_vec()),
            RespValue::BulkString(b"myvalue".to_vec()),
        ];
        handle_set(&set_args, &db).unwrap();

        // EXISTS on existing key
        let result = handle_exists(&exists_args, &db).unwrap();
        assert_eq!(result, RespValue::Integer(1));
    }

    #[tokio::test]
    async fn test_get_handler_wrong_args() {
        let (db, _temp) = test_db();

        // Too many args
        let args = vec![
            RespValue::BulkString(b"GET".to_vec()),
            RespValue::BulkString(b"key1".to_vec()),
            RespValue::BulkString(b"key2".to_vec()),
        ];

        let result = handle_get(&args, &db);
        assert!(result.is_err());

        // Too few args
        let args = vec![RespValue::BulkString(b"GET".to_vec())];

        let result = handle_get(&args, &db);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_set_handler_wrong_args() {
        let (db, _temp) = test_db();

        // Too few args
        let args = vec![
            RespValue::BulkString(b"SET".to_vec()),
            RespValue::BulkString(b"key".to_vec()),
        ];

        let result = handle_set(&args, &db);
        assert!(result.is_err());

        // Too many args
        let args = vec![
            RespValue::BulkString(b"SET".to_vec()),
            RespValue::BulkString(b"key".to_vec()),
            RespValue::BulkString(b"value".to_vec()),
            RespValue::BulkString(b"extra".to_vec()),
        ];

        let result = handle_set(&args, &db);
        assert!(result.is_err());
    }
}
