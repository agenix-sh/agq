//! TCP server implementation with RESP protocol support

use crate::error::{Error, Result};
use crate::resp::{RespParser, RespValue};
use crate::storage::{Database, HashOps, ListOps, SortedSetOps, StringOps};
use crate::workers::InternalJob;
use governor::Quota;
use jsonschema::JSONSchema;
use once_cell::sync::Lazy;
use std::num::NonZeroU32;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

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
            match handle_command(value, &mut authenticated, &session_key, &db).await {
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
async fn handle_command(
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
        "TTL" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_ttl(&args, db)
        }
        "LPUSH" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_lpush(&args, db)
        }
        "RPOP" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_rpop(&args, db)
        }
        "BRPOP" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_brpop(&args, db).await
        }
        "LLEN" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_llen(&args, db)
        }
        "LRANGE" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_lrange(&args, db)
        }
        "LREM" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_lrem(&args, db)
        }
        "RPOPLPUSH" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_rpoplpush(&args, db)
        }
        "BRPOPLPUSH" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_brpoplpush(&args, db).await
        }
        "ZADD" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_zadd(&args, db)
        }
        "ZRANGE" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_zrange(&args, db)
        }
        "ZRANGEBYSCORE" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_zrangebyscore(&args, db)
        }
        "ZREM" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_zrem(&args, db)
        }
        "ZSCORE" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_zscore(&args, db)
        }
        "ZCARD" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_zcard(&args, db)
        }
        "HSET" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_hset(&args, db)
        }
        "HGET" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_hget(&args, db)
        }
        "HDEL" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_hdel(&args, db)
        }
        "HGETALL" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_hgetall(&args, db)
        }
        "HEXISTS" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_hexists(&args, db)
        }
        "HLEN" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_hlen(&args, db)
        }
        "HINCRBY" => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            handle_hincrby(&args, db)
        }
        cmd if cmd.starts_with("PLAN.") => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            match cmd {
                "PLAN.SUBMIT" => handle_plan_submit(&args, db),
                "PLAN.LIST" => handle_plans_list(&args, db),
                "PLAN.GET" => handle_plans_get(&args, db),
                _ => Err(Error::Protocol(format!("Unknown PLAN command: {}", cmd))),
            }
        }
        cmd if cmd.starts_with("ACTION.") => {
            if !*authenticated {
                return Err(Error::NoAuth);
            }
            match cmd {
                "ACTION.SUBMIT" => handle_action_submit(&args, db),
                "ACTION.LIST" => handle_actions_list(&args, db),
                "ACTION.GET" => handle_actions_get(&args, db),
                _ => Err(Error::Protocol(format!("Unknown ACTION command: {}", cmd))),
            }
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

    // Support both raw bytes and hex-encoded strings for compatibility
    // If the key looks like hex (64 chars, all hex digits), try to decode it
    let key_to_compare =
        if provided_key.len() == 64 && provided_key.iter().all(|&b| b.is_ascii_hexdigit()) {
            // Try to decode hex string
            match hex::decode(provided_key) {
                Ok(decoded) => decoded,
                Err(_) => provided_key.clone(), // Fall back to raw bytes if decode fails
            }
        } else {
            // Use raw bytes as-is
            provided_key.clone()
        };

    // Security: Constant-time comparison to prevent timing attacks
    // Pad to same length for constant-time comparison
    let max_len = key_to_compare.len().max(expected_key.len());
    let mut provided_padded = key_to_compare;
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

/// Get current Unix timestamp in seconds
///
/// # Errors
/// Returns an error if system time is before Unix epoch
fn get_current_timestamp_secs() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Protocol(format!("System time error: {e}")))?
        .as_secs())
}

/// Handle SET command
///
/// Syntax: SET key value [EX seconds] [PX milliseconds] [EXAT unix-time-seconds] [PXAT unix-time-milliseconds]
/// Returns: OK
fn handle_set(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() < 3 {
        return Err(Error::InvalidArguments(
            "SET requires at least two arguments".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let RespValue::BulkString(value) = &args[2] else {
        return Err(Error::InvalidArguments(
            "SET value must be a bulk string".to_string(),
        ));
    };

    // Maximum expiry duration: 10 years (prevents resource exhaustion)
    const MAX_EXPIRY_SECONDS: u64 = 365 * 24 * 60 * 60 * 10;

    // Parse optional expiry arguments
    let mut expire_at: Option<u64> = None;
    let mut i = 3;
    while i < args.len() {
        let option = args[i].as_string()?.to_uppercase();
        match option.as_str() {
            "EX" => {
                // Seconds from now
                if i + 1 >= args.len() {
                    return Err(Error::InvalidArguments("EX requires a value".to_string()));
                }
                let seconds: u64 = args[i + 1].as_string()?.parse().map_err(|_| {
                    Error::InvalidArguments("EX value must be an integer".to_string())
                })?;

                // Validate bounds to prevent overflow and resource exhaustion
                if seconds > MAX_EXPIRY_SECONDS {
                    return Err(Error::InvalidArguments(
                        "Expiry time too far in future (max 10 years)".to_string(),
                    ));
                }

                let now = get_current_timestamp_secs()?;

                // Use checked arithmetic to prevent overflow
                let expire_time = now
                    .checked_add(seconds)
                    .ok_or_else(|| Error::InvalidArguments("Expiry time overflow".to_string()))?;

                expire_at = Some(expire_time);
                i += 2;
            }
            "PX" => {
                // Milliseconds from now
                if i + 1 >= args.len() {
                    return Err(Error::InvalidArguments("PX requires a value".to_string()));
                }
                let millis: u64 = args[i + 1].as_string()?.parse().map_err(|_| {
                    Error::InvalidArguments("PX value must be an integer".to_string())
                })?;

                // Convert to seconds, rounding up (ceil division)
                // This ensures PX 500 becomes 1 second, not 0
                let seconds = millis.div_ceil(1000);
                if seconds > MAX_EXPIRY_SECONDS {
                    return Err(Error::InvalidArguments(
                        "Expiry time too far in future (max 10 years)".to_string(),
                    ));
                }

                let now = get_current_timestamp_secs()?;

                // Use checked arithmetic to prevent overflow
                let expire_time = now
                    .checked_add(seconds)
                    .ok_or_else(|| Error::InvalidArguments("Expiry time overflow".to_string()))?;

                expire_at = Some(expire_time);
                i += 2;
            }
            "EXAT" => {
                // Absolute Unix timestamp in seconds
                if i + 1 >= args.len() {
                    return Err(Error::InvalidArguments("EXAT requires a value".to_string()));
                }
                let timestamp: u64 = args[i + 1].as_string()?.parse().map_err(|_| {
                    Error::InvalidArguments("EXAT value must be an integer".to_string())
                })?;

                // Validate timestamp is reasonable (not more than 10 years in future)
                let now = get_current_timestamp_secs()?;
                if timestamp > now + MAX_EXPIRY_SECONDS {
                    return Err(Error::InvalidArguments(
                        "Expiry timestamp too far in future (max 10 years)".to_string(),
                    ));
                }

                expire_at = Some(timestamp);
                i += 2;
            }
            "PXAT" => {
                // Absolute Unix timestamp in milliseconds
                if i + 1 >= args.len() {
                    return Err(Error::InvalidArguments("PXAT requires a value".to_string()));
                }
                let timestamp_millis: u64 = args[i + 1].as_string()?.parse().map_err(|_| {
                    Error::InvalidArguments("PXAT value must be an integer".to_string())
                })?;

                // Convert to seconds, rounding up (ceil division)
                // This ensures sub-second precision doesn't get lost
                let timestamp = timestamp_millis.div_ceil(1000);
                let now = get_current_timestamp_secs()?;
                if timestamp > now + MAX_EXPIRY_SECONDS {
                    return Err(Error::InvalidArguments(
                        "Expiry timestamp too far in future (max 10 years)".to_string(),
                    ));
                }

                expire_at = Some(timestamp);
                i += 2;
            }
            _ => {
                return Err(Error::InvalidArguments(format!(
                    "Unknown SET option: {}",
                    option
                )));
            }
        }
    }

    // Set the key with or without expiry
    if let Some(expire_time) = expire_at {
        db.setex(&key, value, expire_time)?;
    } else {
        db.set(&key, value)?;
    }

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

/// Handle TTL command
///
/// Syntax: TTL key
/// Returns: Integer - TTL in seconds, or -1 if no expiry, or -2 if key doesn't exist
fn handle_ttl(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "TTL requires exactly one argument".to_string(),
        ));
    }

    let key = args[1].as_string()?;

    match db.ttl(&key)? {
        Some(ttl) => Ok(RespValue::Integer(ttl)),
        None => Ok(RespValue::Integer(-2)), // Key doesn't exist
    }
}

/// Handle LPUSH command
///
/// Syntax: LPUSH key value
/// Returns: Integer - length of list after push
fn handle_lpush(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 3 {
        return Err(Error::InvalidArguments(
            "LPUSH requires exactly two arguments".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let RespValue::BulkString(value) = &args[2] else {
        return Err(Error::InvalidArguments(
            "LPUSH value must be a bulk string".to_string(),
        ));
    };

    let length = db.lpush(&key, value)?;
    Ok(RespValue::Integer(length as i64))
}

/// Handle RPOP command
///
/// Syntax: RPOP key
/// Returns: Bulk string value or nil if list is empty
fn handle_rpop(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "RPOP requires exactly one argument".to_string(),
        ));
    }

    let key = args[1].as_string()?;

    match db.rpop(&key)? {
        Some(value) => Ok(RespValue::BulkString(value)),
        None => Ok(RespValue::NullBulkString),
    }
}

/// Handle BRPOP command
///
/// Syntax: BRPOP key timeout
/// Returns: Bulk string value or nil if timeout
async fn handle_brpop(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 3 {
        return Err(Error::InvalidArguments(
            "BRPOP requires exactly two arguments".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let timeout_str = args[2].as_string()?;
    let timeout_secs: u64 = timeout_str.parse().map_err(|_| {
        Error::InvalidArguments("BRPOP timeout must be a non-negative integer".to_string())
    })?;

    match db.brpop(&key, timeout_secs).await? {
        Some(value) => Ok(RespValue::BulkString(value)),
        None => Ok(RespValue::NullBulkString),
    }
}

/// Handle LLEN command
///
/// Syntax: LLEN key
/// Returns: Integer - length of list
fn handle_llen(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "LLEN requires exactly one argument".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let length = db.llen(&key)?;

    Ok(RespValue::Integer(length as i64))
}

/// Handle LRANGE command
///
/// Syntax: LRANGE key start stop
/// Returns: Array of bulk strings
fn handle_lrange(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 4 {
        return Err(Error::InvalidArguments(
            "LRANGE requires exactly three arguments".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let start_str = args[2].as_string()?;
    let stop_str = args[3].as_string()?;

    let start: i64 = start_str
        .parse()
        .map_err(|_| Error::InvalidArguments("LRANGE start must be an integer".to_string()))?;
    let stop: i64 = stop_str
        .parse()
        .map_err(|_| Error::InvalidArguments("LRANGE stop must be an integer".to_string()))?;

    let elements = db.lrange(&key, start, stop)?;
    let resp_elements: Vec<RespValue> = elements.into_iter().map(RespValue::BulkString).collect();

    Ok(RespValue::Array(resp_elements))
}

/// Handle LREM command
///
/// Syntax: LREM key count element
/// Returns: Integer - number of removed elements
///
/// Removes the first `count` occurrences of `element` from list `key`:
/// - If count > 0: Remove elements from head to tail
/// - If count < 0: Remove elements from tail to head
/// - If count = 0: Remove all occurrences
fn handle_lrem(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 4 {
        return Err(Error::InvalidArguments(
            "LREM requires exactly three arguments: key count element".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let count_str = args[2].as_string()?;

    // Extract element as bytes (BulkString)
    let element = match &args[3] {
        RespValue::BulkString(data) => data,
        _ => {
            return Err(Error::InvalidArguments(
                "LREM element must be a bulk string".to_string(),
            ))
        }
    };

    let count: i64 = count_str
        .parse()
        .map_err(|_| Error::InvalidArguments("LREM count must be an integer".to_string()))?;

    let removed = db.lrem(&key, count, element)?;

    Ok(RespValue::Integer(removed))
}

/// Handle RPOPLPUSH command
///
/// Syntax: RPOPLPUSH source destination
/// Returns: Bulk string value or nil if source list is empty
///
/// Atomically pops element from tail of source list and pushes to head of destination list.
/// Both operations occur in a single transaction.
fn handle_rpoplpush(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 3 {
        return Err(Error::InvalidArguments(
            "RPOPLPUSH requires exactly two arguments".to_string(),
        ));
    }

    let source = args[1].as_string()?;
    let destination = args[2].as_string()?;

    match db.rpoplpush(&source, &destination)? {
        Some(value) => Ok(RespValue::BulkString(value)),
        None => Ok(RespValue::NullBulkString),
    }
}

/// Handle BRPOPLPUSH command
///
/// Syntax: BRPOPLPUSH source destination timeout
/// Returns: Bulk string value or nil if timeout
///
/// Blocking version of RPOPLPUSH. Waits for element to become available or timeout.
async fn handle_brpoplpush(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 4 {
        return Err(Error::InvalidArguments(
            "BRPOPLPUSH requires exactly three arguments".to_string(),
        ));
    }

    let source = args[1].as_string()?;
    let destination = args[2].as_string()?;
    let timeout_str = args[3].as_string()?;
    let timeout_secs: u64 = timeout_str.parse().map_err(|_| {
        Error::InvalidArguments("BRPOPLPUSH timeout must be a non-negative integer".to_string())
    })?;

    match db.brpoplpush(&source, &destination, timeout_secs).await? {
        Some(value) => Ok(RespValue::BulkString(value)),
        None => Ok(RespValue::NullBulkString),
    }
}

/// Handle ZADD command
///
/// Syntax: ZADD key score member
/// Returns: Integer - 1 if new member added, 0 if member updated
///
/// # Security
/// - Validates score is a finite number
/// - Rejects NaN, Infinity, -Infinity
fn handle_zadd(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 4 {
        return Err(Error::InvalidArguments(
            "ZADD requires exactly three arguments (key score member)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let score_str = args[2].as_string()?;
    let RespValue::BulkString(member) = &args[3] else {
        return Err(Error::InvalidArguments(
            "ZADD member must be a bulk string".to_string(),
        ));
    };

    // Security: Parse and validate score
    let score: f64 = score_str
        .parse()
        .map_err(|_| Error::InvalidArguments("ZADD score must be a valid number".to_string()))?;

    // Security check is done in db.zadd() which rejects non-finite scores
    let added = db.zadd(&key, score, member)?;
    Ok(RespValue::Integer(added as i64))
}

/// Handle ZRANGE command
///
/// Syntax: ZRANGE key start stop
/// Returns: Array of (member, score) pairs
fn handle_zrange(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 4 {
        return Err(Error::InvalidArguments(
            "ZRANGE requires exactly three arguments (key start stop)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let start_str = args[2].as_string()?;
    let stop_str = args[3].as_string()?;

    let start: i64 = start_str
        .parse()
        .map_err(|_| Error::InvalidArguments("ZRANGE start must be an integer".to_string()))?;
    let stop: i64 = stop_str
        .parse()
        .map_err(|_| Error::InvalidArguments("ZRANGE stop must be an integer".to_string()))?;

    let members = db.zrange(&key, start, stop)?;

    // Return array of alternating member/score pairs (Redis format)
    let mut resp_elements = Vec::with_capacity(members.len() * 2);
    for (member, score) in members {
        resp_elements.push(RespValue::BulkString(member));
        resp_elements.push(RespValue::BulkString(score.to_string().into_bytes()));
    }

    Ok(RespValue::Array(resp_elements))
}

/// Handle ZRANGEBYSCORE command
///
/// Syntax: ZRANGEBYSCORE key min max
/// Returns: Array of (member, score) pairs
///
/// # Security
/// - Validates min/max are finite numbers
fn handle_zrangebyscore(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 4 {
        return Err(Error::InvalidArguments(
            "ZRANGEBYSCORE requires exactly three arguments (key min max)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let min_str = args[2].as_string()?;
    let max_str = args[3].as_string()?;

    // Security: Parse and validate scores
    let min_score: f64 = min_str.parse().map_err(|_| {
        Error::InvalidArguments("ZRANGEBYSCORE min must be a valid number".to_string())
    })?;

    let max_score: f64 = max_str.parse().map_err(|_| {
        Error::InvalidArguments("ZRANGEBYSCORE max must be a valid number".to_string())
    })?;

    // Security check is done in db.zrangebyscore() which rejects non-finite scores
    let members = db.zrangebyscore(&key, min_score, max_score)?;

    // Return array of alternating member/score pairs (Redis format)
    let mut resp_elements = Vec::with_capacity(members.len() * 2);
    for (member, score) in members {
        resp_elements.push(RespValue::BulkString(member));
        resp_elements.push(RespValue::BulkString(score.to_string().into_bytes()));
    }

    Ok(RespValue::Array(resp_elements))
}

/// Handle ZREM command
///
/// Syntax: ZREM key member
/// Returns: Integer - 1 if removed, 0 if member didn't exist
fn handle_zrem(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 3 {
        return Err(Error::InvalidArguments(
            "ZREM requires exactly two arguments (key member)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let RespValue::BulkString(member) = &args[2] else {
        return Err(Error::InvalidArguments(
            "ZREM member must be a bulk string".to_string(),
        ));
    };

    let removed = db.zrem(&key, member)?;
    Ok(RespValue::Integer(removed as i64))
}

/// Handle ZSCORE command
///
/// Syntax: ZSCORE key member
/// Returns: Bulk string score or nil if member doesn't exist
fn handle_zscore(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 3 {
        return Err(Error::InvalidArguments(
            "ZSCORE requires exactly two arguments (key member)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let RespValue::BulkString(member) = &args[2] else {
        return Err(Error::InvalidArguments(
            "ZSCORE member must be a bulk string".to_string(),
        ));
    };

    match db.zscore(&key, member)? {
        Some(score) => Ok(RespValue::BulkString(score.to_string().into_bytes())),
        None => Ok(RespValue::NullBulkString),
    }
}

/// Handle ZCARD command
///
/// Syntax: ZCARD key
/// Returns: Integer - number of members in sorted set
fn handle_zcard(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "ZCARD requires exactly one argument (key)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let count = db.zcard(&key)?;
    Ok(RespValue::Integer(count as i64))
}

/// Handle HSET command
///
/// Syntax: HSET key field value
/// Returns: Integer - 1 if new field created, 0 if field updated
fn handle_hset(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 4 {
        return Err(Error::InvalidArguments(
            "HSET requires exactly three arguments (key field value)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let field = args[2].as_string()?;
    let RespValue::BulkString(value) = &args[3] else {
        return Err(Error::InvalidArguments(
            "HSET value must be a bulk string".to_string(),
        ));
    };

    let created = db.hset(&key, &field, value)?;
    Ok(RespValue::Integer(created as i64))
}

/// Handle HGET command
///
/// Syntax: HGET key field
/// Returns: Bulk string value or nil if field doesn't exist
fn handle_hget(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 3 {
        return Err(Error::InvalidArguments(
            "HGET requires exactly two arguments (key field)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let field = args[2].as_string()?;

    match db.hget(&key, &field)? {
        Some(value) => Ok(RespValue::BulkString(value)),
        None => Ok(RespValue::NullBulkString),
    }
}

/// Handle HDEL command
///
/// Syntax: HDEL key field
/// Returns: Integer - 1 if field was deleted, 0 if field didn't exist
fn handle_hdel(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 3 {
        return Err(Error::InvalidArguments(
            "HDEL requires exactly two arguments (key field)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let field = args[2].as_string()?;

    let deleted = db.hdel(&key, &field)?;
    Ok(RespValue::Integer(deleted as i64))
}

/// Handle HGETALL command
///
/// Syntax: HGETALL key
/// Returns: Array of alternating field/value pairs
fn handle_hgetall(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "HGETALL requires exactly one argument (key)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let fields = db.hgetall(&key)?;

    // Return array of alternating field/value pairs (Redis format)
    let mut resp_elements = Vec::with_capacity(fields.len() * 2);
    for (field, value) in fields {
        resp_elements.push(RespValue::BulkString(field.into_bytes()));
        resp_elements.push(RespValue::BulkString(value));
    }

    Ok(RespValue::Array(resp_elements))
}

/// Handle HEXISTS command
///
/// Syntax: HEXISTS key field
/// Returns: Integer - 1 if field exists, 0 if it doesn't
fn handle_hexists(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 3 {
        return Err(Error::InvalidArguments(
            "HEXISTS requires exactly two arguments (key field)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let field = args[2].as_string()?;

    let exists = db.hexists(&key, &field)?;
    Ok(RespValue::Integer(i64::from(exists)))
}

/// Handle HLEN command
///
/// Syntax: HLEN key
/// Returns: Integer - number of fields in hash
fn handle_hlen(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "HLEN requires exactly one argument (key)".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let count = db.hlen(&key)?;
    Ok(RespValue::Integer(count as i64))
}

fn handle_hincrby(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 4 {
        return Err(Error::InvalidArguments(
            "HINCRBY requires exactly three arguments: key field increment".to_string(),
        ));
    }

    let key = args[1].as_string()?;
    let field = args[2].as_string()?;
    let increment_str = args[3].as_string()?;

    // Validate key length (allow more liberal characters for namespacing like "stats:plan_id")
    if key.is_empty() || key.len() > 256 {
        return Err(Error::InvalidArguments(
            "HINCRBY key must be between 1 and 256 characters".to_string(),
        ));
    }

    // Validate field length and characters
    if field.is_empty() || field.len() > 256 {
        return Err(Error::InvalidArguments(
            "HINCRBY field must be between 1 and 256 characters".to_string(),
        ));
    }

    // Only allow printable ASCII characters (no control characters)
    if !key.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Err(Error::InvalidArguments(
            "HINCRBY key contains invalid characters".to_string(),
        ));
    }

    if !field.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Err(Error::InvalidArguments(
            "HINCRBY field contains invalid characters".to_string(),
        ));
    }

    let increment: i64 = increment_str.parse().map_err(|_| {
        Error::InvalidArguments("HINCRBY increment must be an integer".to_string())
    })?;

    let new_value = db.hincrby(&key, &field, increment)?;
    Ok(RespValue::Integer(new_value))
}

/// Maximum plan JSON size (1MB)
const MAX_PLAN_SIZE: usize = 1024 * 1024;

/// Plan JSON schema for validation (Layer 2 - Plan templates)
///
/// Validates Plan definitions submitted via PLAN.SUBMIT.
/// Plans are templates that are stored and later used to create Jobs.
///
/// **IMPORTANT**: This is the Plan schema (Layer 2), NOT the Job schema (Layer 3).
/// - Plans do NOT have job_id (that's added when AGQ creates Jobs from Plans)
/// - Plans have plan_id, description, and tasks
/// - Jobs have job_id, plan_id, description, and tasks (see job-schema.md)
///
/// # Security Constraints
/// - Maximum 100 tasks per plan (per canonical spec)
/// - Maximum 256 characters for command names
/// - Maximum 100 args per task
/// - Maximum 65KB per arg (prevents memory exhaustion)
/// - Minimum 1 task (non-empty plans only)
const PLAN_SCHEMA: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["plan_id", "tasks"],
  "properties": {
    "plan_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 64
    },
    "plan_description": {
      "type": "string",
      "maxLength": 1024
    },
    "tasks": {
      "type": "array",
      "minItems": 1,
      "maxItems": 100,
      "items": {
        "type": "object",
        "required": ["task_number", "command"],
        "properties": {
          "task_number": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100
          },
          "command": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256
          },
          "args": {
            "type": "array",
            "maxItems": 100,
            "items": {
              "type": "string",
              "maxLength": 65536
            }
          },
          "timeout_secs": {
            "type": "integer",
            "minimum": 1,
            "maximum": 3600
          },
          "input_from_task": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100
          }
        }
      }
    }
  }
}"#;

/// Lazily compiled JSON schema validator for Plan validation
///
/// Compiled once at first use to avoid overhead on every request.
/// Validates against PLAN_SCHEMA defined above.
static PLAN_VALIDATOR: Lazy<JSONSchema> = Lazy::new(|| {
    let schema: serde_json::Value =
        serde_json::from_str(PLAN_SCHEMA).expect("PLAN_SCHEMA must be valid JSON");
    JSONSchema::compile(&schema).expect("PLAN_SCHEMA must compile successfully")
});

/// Rate limiter for PLAN.SUBMIT command (1000 plans per minute globally)
///
/// Prevents flooding the internal queue with plan submissions.
/// Uses governor crate for token bucket rate limiting.
///
/// # Rate Limit
/// - 1000 plans/minute globally (~16.7 plans/second)
/// - Returns RateLimitExceeded error when exceeded
static PLAN_SUBMIT_LIMITER: Lazy<
    governor::RateLimiter<
        governor::state::direct::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >,
> = Lazy::new(|| governor::RateLimiter::direct(Quota::per_minute(NonZeroU32::new(1000).unwrap())));

/// Handle PLAN.SUBMIT command
///
/// Syntax: PLAN.SUBMIT <plan_json>
/// Returns: plan_id (unique identifier for the submitted plan)
///
/// # Security
/// - Validates JSON schema against Plan specification
/// - Enforces maximum plan size (1MB)
/// - Generates cryptographically secure plan IDs
///
/// # Implementation
/// This follows the internal queue worker pattern:
/// 1. Validate input
/// 2. Generate plan_id
/// 3. Push to internal queue (agq:internal:plan.submit)
/// 4. Return plan_id immediately (async processing)
fn handle_plan_submit(args: &[RespValue], db: &Database) -> Result<RespValue> {
    // Security: Check rate limit before processing
    if PLAN_SUBMIT_LIMITER.check().is_err() {
        warn!("PLAN.SUBMIT rate limit exceeded");
        return Err(Error::Protocol(
            "Rate limit exceeded for PLAN.SUBMIT (max 1000/minute)".to_string(),
        ));
    }

    // Validate arguments
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "PLAN.SUBMIT requires exactly one argument (plan JSON)".to_string(),
        ));
    }

    let plan_json = args[1].as_string()?;

    // Security: Enforce size limits to prevent resource exhaustion
    if plan_json.len() > MAX_PLAN_SIZE {
        return Err(Error::InvalidArguments(format!(
            "Plan JSON too large (max {} bytes)",
            MAX_PLAN_SIZE
        )));
    }

    // Validate JSON is well-formed
    let plan_value: serde_json::Value = serde_json::from_str(&plan_json)
        .map_err(|e| Error::InvalidArguments(format!("Invalid JSON: {}", e)))?;

    // Validate against Plan schema (using lazy-compiled validator)
    if let Err(errors) = PLAN_VALIDATOR.validate(&plan_value) {
        let error_msgs: Vec<String> = errors.map(|e| format!("{}", e)).collect();
        return Err(Error::InvalidArguments(format!(
            "Plan validation failed: {}",
            error_msgs.join(", ")
        )));
    }

    // Extract plan_id from JSON (required by schema)
    let plan_id = plan_value["plan_id"]
        .as_str()
        .ok_or_else(|| Error::InvalidArguments("plan_id field is required".to_string()))?
        .to_string();

    // Validate plan_id format
    validate_identifier(&plan_id, "plan_id")?;

    // Create internal job
    let internal_job = InternalJob {
        id: Uuid::new_v4().to_string(),
        operation: "plan.submit".to_string(),
        entity_id: plan_id.clone(),
        payload: plan_json.to_string(),
        timestamp: get_current_timestamp_secs()?,
        retry_count: 0,
        max_retries: 3,
    };

    // Serialize job to JSON
    let job_json = serde_json::to_vec(&internal_job)
        .map_err(|e| Error::Protocol(format!("Failed to serialize internal job: {}", e)))?;

    // Push to internal queue
    db.lpush("agq:internal:plan.submit", &job_json)?;

    debug!("PLAN.SUBMIT -> {} (queued for processing)", plan_id);

    // Return plan_id immediately (processing continues asynchronously)
    Ok(RespValue::BulkString(plan_id.into_bytes()))
}

/// Validate an identifier (plan_id, action_id, job_id, etc.)
///
/// # Security
/// Identifiers must be:
/// - 1-64 characters long
/// - Alphanumeric with hyphens, underscores only
/// - No special characters (prevents injection attacks)
///
/// # Arguments
/// * `id` - The identifier to validate
/// * `field_name` - Name of the field for error messages
///
/// # Returns
/// Ok(()) if valid, Err with detailed message if invalid
fn validate_identifier(id: &str, field_name: &str) -> Result<()> {
    // Check length
    if id.is_empty() || id.len() > 64 {
        return Err(Error::InvalidArguments(format!(
            "{} must be between 1 and 64 characters",
            field_name
        )));
    }

    // Check characters (alphanumeric + hyphen + underscore only)
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::InvalidArguments(format!(
            "{} contains invalid characters (only alphanumeric, hyphens, and underscores allowed)",
            field_name
        )));
    }

    Ok(())
}

/// Maximum size for a single input in ACTION.SUBMIT (10MB)
///
/// Prevents resource exhaustion attacks where large inputs bypass
/// the 100-input limit (100 * 10MB = 1GB max per Action)
const MAX_INPUT_SIZE: usize = 10 * 1024 * 1024; // 10MB

/// Rate limiter for ACTION.SUBMIT commands (dedicated)
///
/// Separate from PLAN_SUBMIT to prevent DoS attacks that target
/// the more expensive ACTION.SUBMIT operation (creates multiple Jobs)
///
/// # Rate Limit
/// - 100 actions/minute globally (~1.67 actions/second)
/// - Lower than PLAN_SUBMIT due to higher cost
static ACTION_SUBMIT_LIMITER: Lazy<
    governor::RateLimiter<
        governor::state::direct::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >,
> = Lazy::new(|| governor::RateLimiter::direct(Quota::per_minute(NonZeroU32::new(100).unwrap())));

/// Handle ACTION.SUBMIT command (Layer 4 - Action execution)
///
/// Syntax: ACTION.SUBMIT <action_json>
/// Returns: JSON response with action_id and created job_ids
///
/// # Action JSON Format
/// ```json
/// {
///   "action_id": "action-uuid",
///   "plan_id": "plan-uuid",
///   "inputs": [
///     {"file": "/path/to/file1.txt"},
///     {"file": "/path/to/file2.txt"}
///   ]
/// }
/// ```
///
/// # Implementation
/// 1. Validate action JSON structure
/// 2. Verify plan_id exists in database
/// 3. Create N Jobs (one per input in inputs array)
/// 4. Each Job = Plan template + job_id + specific input data
/// 5. Enqueue Jobs to queue:ready for worker dispatch
/// 6. Return action summary
///
/// # Security
/// - Validates JSON structure
/// - Validates identifiers (prevents injection attacks)
/// - Checks for duplicate action_id (prevents overwrites)
/// - Verifies Plan exists before creating Jobs
/// - Enforces maximum inputs limit (100 per Action)
/// - Enforces per-input size limits (10MB per input)
/// - Dedicated rate limiter (100/minute)
fn handle_action_submit(args: &[RespValue], db: &Database) -> Result<RespValue> {
    // Security: Check rate limit (dedicated ACTION_SUBMIT limiter)
    if ACTION_SUBMIT_LIMITER.check().is_err() {
        warn!("ACTION.SUBMIT rate limit exceeded");
        return Err(Error::Protocol(
            "Rate limit exceeded for ACTION.SUBMIT (max 100/minute)".to_string(),
        ));
    }

    // Validate arguments
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "ACTION.SUBMIT requires exactly one argument (action JSON)".to_string(),
        ));
    }

    let action_json = args[1].as_string()?;

    // Parse action JSON
    let action_value: serde_json::Value = serde_json::from_str(&action_json)
        .map_err(|e| Error::InvalidArguments(format!("Invalid JSON: {}", e)))?;

    // Extract required fields
    let action_id = action_value["action_id"]
        .as_str()
        .ok_or_else(|| Error::InvalidArguments("Missing required field: action_id".to_string()))?;

    let plan_id = action_value["plan_id"]
        .as_str()
        .ok_or_else(|| Error::InvalidArguments("Missing required field: plan_id".to_string()))?;

    // Security: Validate identifiers to prevent injection attacks
    validate_identifier(action_id, "action_id")?;
    validate_identifier(plan_id, "plan_id")?;

    let inputs = action_value["inputs"].as_array().ok_or_else(|| {
        Error::InvalidArguments("Missing or invalid field: inputs (must be array)".to_string())
    })?;

    // Security: Enforce maximum inputs limit
    if inputs.is_empty() {
        return Err(Error::InvalidArguments(
            "inputs array must contain at least one input".to_string(),
        ));
    }

    if inputs.len() > 100 {
        return Err(Error::InvalidArguments(
            "inputs array exceeds maximum of 100 inputs per Action".to_string(),
        ));
    }

    // Security: Validate per-input size to prevent resource exhaustion
    for (idx, input) in inputs.iter().enumerate() {
        let input_str = serde_json::to_string(input)
            .map_err(|e| Error::Protocol(format!("Failed to serialize input {}: {}", idx, e)))?;

        if input_str.len() > MAX_INPUT_SIZE {
            return Err(Error::InvalidArguments(format!(
                "Input {} exceeds maximum size of {} bytes (got {} bytes)",
                idx,
                MAX_INPUT_SIZE,
                input_str.len()
            )));
        }
    }

    // Verify Plan exists and retrieve JSON (single operation to avoid TOCTOU)
    let plan_key = format!("plan:{}", plan_id);
    let plan_json_bytes = db
        .hget(&plan_key, "json")?
        .ok_or_else(|| Error::InvalidArguments(format!("Plan not found: {}", plan_id)))?;

    // Security: Check for duplicate action_id to prevent overwrites
    // (done after plan existence check to avoid leaking info about action_ids)
    let action_key = format!("action:{}", action_id);
    let action_exists = db.hget(&action_key, "status")?.is_some();
    if action_exists {
        return Err(Error::InvalidArguments(format!(
            "Action ID already exists: {}",
            action_id
        )));
    }

    let plan_json = std::str::from_utf8(&plan_json_bytes)
        .map_err(|e| Error::Protocol(format!("Plan JSON is not valid UTF-8: {}", e)))?;

    let plan_value: serde_json::Value = serde_json::from_str(plan_json)
        .map_err(|e| Error::Protocol(format!("Plan JSON is invalid: {}", e)))?;

    // Create Jobs (one per input)
    let mut job_ids = Vec::new();

    for (idx, input) in inputs.iter().enumerate() {
        // Security: Safe conversion for input_index (already bounded by 100 input limit)
        let input_index =
            u64::try_from(idx).map_err(|_| Error::Protocol("Input index overflow".to_string()))?;

        // Generate unique job_id
        let job_id = format!("job_{}", Uuid::new_v4().simple());

        // Create Job = Plan + job_id + input
        // Per Layer 2→3 transition: Plans don't have job_id, Jobs do
        let mut job_value = plan_value.clone();
        job_value["job_id"] = serde_json::Value::String(job_id.clone());
        job_value["input"] = input.clone();
        job_value["input_index"] = serde_json::Value::Number(input_index.into());

        // Serialize Job to JSON
        let job_json = serde_json::to_string(&job_value)
            .map_err(|e| Error::Protocol(format!("Failed to serialize Job: {}", e)))?;

        // Enqueue Job to queue:ready
        db.lpush("queue:ready", job_json.as_bytes())?;

        // Store Job metadata in hash
        let job_key = format!("job:{}", job_id);
        db.hset(&job_key, "action_id", action_id.as_bytes())?;
        db.hset(&job_key, "plan_id", plan_id.as_bytes())?;
        db.hset(&job_key, "status", b"pending")?;
        let timestamp = get_current_timestamp_secs()?;
        db.hset(&job_key, "created_at", timestamp.to_string().as_bytes())?;

        // Index Job by action_id (for querying jobs by action)
        let action_jobs_key = format!("action:{}:jobs", action_id);
        db.lpush(&action_jobs_key, job_id.as_bytes())?;

        job_ids.push(job_id);
    }

    // Store Action metadata
    let action_key = format!("action:{}", action_id);
    db.hset(&action_key, "plan_id", plan_id.as_bytes())?;
    db.hset(
        &action_key,
        "jobs_created",
        job_ids.len().to_string().as_bytes(),
    )?;
    db.hset(&action_key, "status", b"running")?;
    let timestamp = get_current_timestamp_secs()?;
    db.hset(&action_key, "created_at", timestamp.to_string().as_bytes())?;

    // Track plan usage statistics
    let plan_stats_key = format!("plan:{}:stats", plan_id);
    db.hincrby(&plan_stats_key, "total_actions", 1)?;
    db.hincrby(&plan_stats_key, "total_jobs", job_ids.len() as i64)?;
    db.hset(&plan_stats_key, "last_used", timestamp.to_string().as_bytes())?;

    // Index action by plan_id (for querying actions by plan)
    let plan_actions_key = format!("plan:{}:actions", plan_id);
    db.lpush(&plan_actions_key, action_id.as_bytes())?;

    // Index action in global sorted set (for ACTION.LIST)
    db.zadd("actions:all", timestamp as f64, action_id.as_bytes())?;

    // Build response JSON
    let response = serde_json::json!({
        "action_id": action_id,
        "plan_id": plan_id,
        "jobs_created": job_ids.len(),
        "job_ids": job_ids
    });

    let response_json = serde_json::to_string(&response)
        .map_err(|_| Error::Protocol("Failed to serialize response".to_string()))?;

    debug!(
        "ACTION.SUBMIT -> {} (created {} jobs)",
        action_id,
        job_ids.len()
    );

    Ok(RespValue::BulkString(response_json.into_bytes()))
}

/// Handle PLAN.LIST command
///
/// Usage: PLAN.LIST [offset] [limit]
/// - offset: Start index (default: 0)
/// - limit: Max results (default: 50, max: 100)
///
/// Returns list of stored plans with metadata
fn handle_plans_list(args: &[RespValue], db: &Database) -> Result<RespValue> {
    const DEFAULT_LIMIT: i64 = 50;
    const MAX_LIMIT: i64 = 100;

    // Parse optional offset and limit arguments
    let offset = if args.len() > 1 {
        args[1].as_string()?.parse::<i64>()
            .map_err(|_| Error::InvalidArguments("offset must be a non-negative integer".to_string()))?
    } else {
        0
    };

    let limit = if args.len() > 2 {
        let requested = args[2].as_string()?.parse::<i64>()
            .map_err(|_| Error::InvalidArguments("limit must be a positive integer".to_string()))?;
        requested.min(MAX_LIMIT) // Enforce maximum
    } else {
        DEFAULT_LIMIT
    };

    if offset < 0 || limit <= 0 {
        return Err(Error::InvalidArguments("offset must be >= 0 and limit must be > 0".to_string()));
    }

    // Get paginated plan IDs from the plans:all sorted set (sorted by creation time)
    // Use checked arithmetic to prevent integer overflow
    let stop = offset.checked_add(limit)
        .and_then(|sum| sum.checked_sub(1))
        .ok_or_else(|| Error::InvalidArguments("Pagination range overflow".to_string()))?;
    let plan_entries = db.zrange("plans:all", offset, stop)?;

    let mut plans = Vec::new();

    for (member, _score) in plan_entries {
        let plan_id = String::from_utf8(member)
            .map_err(|_| Error::Protocol("Invalid plan_id encoding".to_string()))?;

        let plan_key = format!("plan:{}", plan_id);

        // Check if plan still exists (may have been deleted)
        if !db.hexists(&plan_key, "json")? {
            continue;
        }

        // Get task_count from stored metadata (no JSON parsing needed)
        let task_count_bytes = db.hget(&plan_key, "task_count")?
            .unwrap_or_else(|| b"0".to_vec());
        let task_count = std::str::from_utf8(&task_count_bytes)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // Get description from stored metadata
        let description_bytes = db.hget(&plan_key, "plan_description")?
            .unwrap_or_default();
        let description = std::str::from_utf8(&description_bytes)
            .unwrap_or("");

        // Get creation timestamp
        let created_at_bytes = db.hget(&plan_key, "created_at")?;
        let created_at = if let Some(bytes) = created_at_bytes {
            let ts_str = std::str::from_utf8(&bytes)
                .map_err(|_| Error::Protocol("Invalid timestamp encoding".to_string()))?;
            ts_str.parse::<u64>()
                .map_err(|_| Error::Protocol("Invalid timestamp format".to_string()))?
        } else {
            0
        };

        // Get usage statistics
        let plan_stats_key = format!("plan:{}:stats", plan_id);

        let total_actions = if let Some(bytes) = db.hget(&plan_stats_key, "total_actions")? {
            std::str::from_utf8(&bytes).ok()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0)
        } else {
            0
        };

        let total_jobs = if let Some(bytes) = db.hget(&plan_stats_key, "total_jobs")? {
            std::str::from_utf8(&bytes).ok()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0)
        } else {
            0
        };

        let last_used = if let Some(bytes) = db.hget(&plan_stats_key, "last_used")? {
            std::str::from_utf8(&bytes).ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
        } else {
            0
        };

        let plan_info = serde_json::json!({
            "plan_id": plan_id,
            "plan_description": description,
            "task_count": task_count,
            "created_at": created_at,
            "total_actions": total_actions,
            "total_jobs": total_jobs,
            "last_used": last_used,
        });

        plans.push(plan_info);
    }

    let response = serde_json::to_string(&plans)
        .map_err(|_| Error::Protocol("Failed to serialize response".to_string()))?;

    debug!("PLAN.LIST -> {} plans", plans.len());
    Ok(RespValue::BulkString(response.into_bytes()))
}

/// Handle PLAN.GET command
///
/// Returns full plan details for a specific plan_id
fn handle_plans_get(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(
            "PLAN.GET requires exactly one argument (plan_id)".to_string(),
        ));
    }

    let plan_id = args[1].as_string()?;
    validate_identifier(&plan_id, "plan_id")?;

    let plan_key = format!("plan:{}", plan_id);

    // Get plan JSON
    let json_bytes = db.hget(&plan_key, "json")?
        .ok_or_else(|| Error::InvalidArguments(format!("Plan not found: {}", plan_id)))?;

    let json_str = std::str::from_utf8(&json_bytes)
        .map_err(|_| Error::Protocol("Invalid plan JSON encoding".to_string()))?;

    let mut plan_value: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|_| Error::Protocol("Invalid plan JSON format".to_string()))?;

    // Add metadata
    let created_at_bytes = db.hget(&plan_key, "created_at")?;
    if let Some(bytes) = created_at_bytes {
        let ts_str = std::str::from_utf8(&bytes)
            .map_err(|_| Error::Protocol("Invalid timestamp encoding".to_string()))?;
        let created_at = ts_str.parse::<u64>()
            .map_err(|_| Error::Protocol("Invalid timestamp format".to_string()))?;

        // Get usage statistics
        let plan_stats_key = format!("plan:{}:stats", plan_id);

        let total_actions = if let Some(bytes) = db.hget(&plan_stats_key, "total_actions")? {
            std::str::from_utf8(&bytes).ok()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0)
        } else {
            0
        };

        let total_jobs = if let Some(bytes) = db.hget(&plan_stats_key, "total_jobs")? {
            std::str::from_utf8(&bytes).ok()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0)
        } else {
            0
        };

        let last_used = if let Some(bytes) = db.hget(&plan_stats_key, "last_used")? {
            std::str::from_utf8(&bytes).ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
        } else {
            0
        };

        plan_value["metadata"] = serde_json::json!({
            "created_at": created_at,
            "total_actions": total_actions,
            "total_jobs": total_jobs,
            "last_used": last_used,
        });
    }

    let response = serde_json::to_string(&plan_value)
        .map_err(|_| Error::Protocol("Failed to serialize response".to_string()))?;

    debug!("PLAN.GET {} -> {} bytes", plan_id, response.len());
    Ok(RespValue::BulkString(response.into_bytes()))
}

/// Handle ACTION.LIST command
///
/// Usage: ACTION.LIST [status] [offset] [limit]
/// - status: Optional status filter (pending/running/completed/failed)
/// - offset: Start index (default: 0)
/// - limit: Max actions to return (default: 100, max: 1000)
///
/// Returns list of all actions (optionally filtered by status) with job progress
fn handle_actions_list(args: &[RespValue], db: &Database) -> Result<RespValue> {
    const DEFAULT_LIMIT: i64 = 100;
    const MAX_LIMIT: i64 = 1000;

    // Parse optional status filter
    let status_filter = if args.len() > 1 {
        let status = args[1].as_string()?;
        if !status.is_empty() && status != "all" {
            // Validate status value
            if !["pending", "running", "completed", "failed"].contains(&status.as_str()) {
                return Err(Error::InvalidArguments(
                    "status must be one of: pending, running, completed, failed, all".to_string(),
                ));
            }
            Some(status)
        } else {
            None
        }
    } else {
        None
    };

    // Parse pagination arguments
    let offset = if args.len() > 2 {
        args[2].as_string()?.parse::<i64>()
            .map_err(|_| Error::InvalidArguments("offset must be a non-negative integer".to_string()))?
    } else {
        0
    };

    let limit = if args.len() > 3 {
        let requested = args[3].as_string()?.parse::<i64>()
            .map_err(|_| Error::InvalidArguments("limit must be a positive integer".to_string()))?;
        requested.min(MAX_LIMIT)
    } else {
        DEFAULT_LIMIT
    };

    if offset < 0 {
        return Err(Error::InvalidArguments("offset must be non-negative".to_string()));
    }

    if limit <= 0 {
        return Err(Error::InvalidArguments("limit must be positive".to_string()));
    }

    // Get all actions from the sorted set (indexed by timestamp)
    // Use checked arithmetic to prevent overflow
    let stop = offset.checked_add(limit)
        .and_then(|sum| sum.checked_sub(1))
        .ok_or_else(|| Error::InvalidArguments("Pagination range overflow".to_string()))?;

    let action_entries = db.zrange("actions:all", offset, stop)?;

    let mut actions: Vec<serde_json::Value> = Vec::new();

    for (action_id_bytes, _score) in action_entries {
        let action_id = std::str::from_utf8(&action_id_bytes)
            .map_err(|_| Error::Protocol("Invalid action_id encoding".to_string()))?;

        let action_key = format!("action:{}", action_id);

        // Get action metadata
        let plan_id = db.hget(&action_key, "plan_id")?
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().map(|s| s.to_string()));

        let status = db.hget(&action_key, "status")?
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().map(|s| s.to_string()))
            .unwrap_or_else(|| "pending".to_string());

        let created_at = if let Some(bytes) = db.hget(&action_key, "created_at")? {
            std::str::from_utf8(&bytes).ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
        } else {
            0
        };

        // Apply status filter
        if let Some(ref filter_status) = status_filter {
            if &status != filter_status {
                continue; // Skip actions that don't match filter
            }
        }

        // Calculate job progress
        let action_jobs_key = format!("action:{}:jobs", action_id);
        let job_ids = db.lrange(&action_jobs_key, 0, -1)?;

        let mut jobs_completed = 0;
        let mut jobs_failed = 0;
        let mut jobs_pending = 0;

        for job_id_bytes in &job_ids {
            let job_id = std::str::from_utf8(job_id_bytes)
                .map_err(|_| Error::Protocol("Invalid job_id encoding".to_string()))?;
            let job_key = format!("job:{}", job_id);

            let job_status = if let Some(bytes) = db.hget(&job_key, "status")? {
                String::from_utf8(bytes)
                    .unwrap_or_else(|_| "pending".to_string())
            } else {
                "pending".to_string()
            };

            match job_status.as_str() {
                "completed" => jobs_completed += 1,
                "failed" => jobs_failed += 1,
                _ => jobs_pending += 1,
            }
        }

        let action_info = serde_json::json!({
            "action_id": action_id,
            "plan_id": plan_id,
            "status": status,
            "created_at": created_at,
            "jobs_total": job_ids.len(),
            "jobs_completed": jobs_completed,
            "jobs_failed": jobs_failed,
            "jobs_pending": jobs_pending,
        });

        actions.push(action_info);
    }

    let response = serde_json::to_string(&actions)
        .map_err(|_| Error::Protocol("Failed to serialize response".to_string()))?;

    debug!("ACTION.LIST -> {} actions", actions.len());
    Ok(RespValue::BulkString(response.into_bytes()))
}

/// Handle ACTION.GET command
///
/// Usage: ACTION.GET <action_id> [job_offset] [job_limit]
/// - action_id: The action identifier (required)
/// - job_offset: Start index for job_ids (default: 0)
/// - job_limit: Max job_ids to return (default: 100, max: 1000)
///
/// Returns action details with paginated job list
fn handle_actions_get(args: &[RespValue], db: &Database) -> Result<RespValue> {
    if args.len() < 2 {
        return Err(Error::InvalidArguments(
            "ACTION.GET requires at least one argument (action_id)".to_string(),
        ));
    }

    const DEFAULT_JOB_LIMIT: i64 = 100;
    const MAX_JOB_LIMIT: i64 = 1000;

    let action_id = args[1].as_string()?;
    validate_identifier(&action_id, "action_id")?;

    // Parse optional job pagination arguments
    let job_offset = if args.len() > 2 {
        args[2].as_string()?.parse::<i64>()
            .map_err(|_| Error::InvalidArguments("job_offset must be a non-negative integer".to_string()))?
    } else {
        0
    };

    let job_limit = if args.len() > 3 {
        let requested = args[3].as_string()?.parse::<i64>()
            .map_err(|_| Error::InvalidArguments("job_limit must be a positive integer".to_string()))?;
        requested.min(MAX_JOB_LIMIT) // Enforce maximum
    } else {
        DEFAULT_JOB_LIMIT
    };

    if job_offset < 0 || job_limit <= 0 {
        return Err(Error::InvalidArguments("job_offset must be >= 0 and job_limit must be > 0".to_string()));
    }

    let action_key = format!("action:{}", action_id);

    // Get action metadata
    let plan_id_bytes = db.hget(&action_key, "plan_id")?
        .ok_or_else(|| Error::InvalidArguments(format!("Action not found: {}", action_id)))?;

    let plan_id = String::from_utf8(plan_id_bytes)
        .map_err(|_| Error::Protocol("Invalid plan_id encoding".to_string()))?;

    let status_bytes = db.hget(&action_key, "status")?
        .unwrap_or_else(|| b"unknown".to_vec());
    let status = String::from_utf8(status_bytes)
        .map_err(|_| Error::Protocol("Invalid status encoding".to_string()))?;

    // Note: We calculate actual job counts from the jobs list, not from jobs_created field

    let created_at_bytes = db.hget(&action_key, "created_at")?;
    let created_at = if let Some(bytes) = created_at_bytes {
        let ts_str = std::str::from_utf8(&bytes)
            .map_err(|_| Error::Protocol("Invalid timestamp encoding".to_string()))?;
        ts_str.parse::<u64>()
            .map_err(|_| Error::Protocol("Invalid timestamp format".to_string()))?
    } else {
        0
    };

    // Get all job IDs to calculate status breakdown
    let action_jobs_key = format!("action:{}:jobs", action_id);
    let all_job_ids_bytes = db.lrange(&action_jobs_key, 0, -1)?;

    // Calculate job status breakdown
    let mut jobs_completed = 0;
    let mut jobs_failed = 0;
    let mut jobs_pending = 0;

    for job_id_bytes in &all_job_ids_bytes {
        let job_id = std::str::from_utf8(job_id_bytes)
            .map_err(|_| Error::Protocol("Invalid job_id encoding".to_string()))?;
        let job_key = format!("job:{}", job_id);

        let job_status = if let Some(bytes) = db.hget(&job_key, "status")? {
            String::from_utf8(bytes)
                .unwrap_or_else(|_| "pending".to_string())
        } else {
            "pending".to_string()
        };

        match job_status.as_str() {
            "completed" => jobs_completed += 1,
            "failed" => jobs_failed += 1,
            _ => jobs_pending += 1,
        }
    }

    // Get paginated job list for job_ids array
    // Use checked arithmetic to prevent integer overflow
    let job_stop = job_offset.checked_add(job_limit)
        .and_then(|sum| sum.checked_sub(1))
        .ok_or_else(|| Error::InvalidArguments("Job pagination range overflow".to_string()))?;
    let job_ids_bytes = db.lrange(&action_jobs_key, job_offset, job_stop)?;

    // Convert job IDs with proper error handling (not silent)
    let mut job_ids = Vec::new();
    for bytes in job_ids_bytes {
        let job_id = String::from_utf8(bytes)
            .map_err(|_| Error::Protocol("Invalid job_id encoding".to_string()))?;
        job_ids.push(job_id);
    }

    let response = serde_json::json!({
        "action_id": action_id,
        "plan_id": plan_id,
        "status": status,
        "created_at": created_at,
        "summary": {
            "jobs_total": all_job_ids_bytes.len(),
            "jobs_completed": jobs_completed,
            "jobs_failed": jobs_failed,
            "jobs_pending": jobs_pending,
        },
        "job_ids": job_ids,
        "job_ids_offset": job_offset,
        "job_ids_limit": job_limit,
        "job_ids_returned": job_ids.len(),
    });

    let response_json = serde_json::to_string(&response)
        .map_err(|_| Error::Protocol("Failed to serialize response".to_string()))?;

    debug!("ACTION.GET {} -> {}/{} jobs (completed: {}, failed: {}, pending: {})",
           action_id, job_ids.len(), all_job_ids_bytes.len(), jobs_completed, jobs_failed, jobs_pending);
    Ok(RespValue::BulkString(response_json.into_bytes()))
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
    async fn test_auth_handler_hex_encoded() {
        let mut authenticated = false;
        // 32-byte key
        let session_key =
            hex::decode("4f90ccd2c864cee924523ec901c450f543753103b3c0da793561b1f9e3eaf579")
                .unwrap();

        // Client sends hex-encoded string (64 chars)
        let args = vec![
            RespValue::BulkString(b"AUTH".to_vec()),
            RespValue::BulkString(
                b"4f90ccd2c864cee924523ec901c450f543753103b3c0da793561b1f9e3eaf579".to_vec(),
            ),
        ];

        let result = handle_auth(&args, &mut authenticated, &session_key).unwrap();

        assert_eq!(result, RespValue::SimpleString("OK".to_string()));
        assert!(authenticated);
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

        let result = handle_command(value, &mut authenticated, &session_key, &db).await;

        assert!(matches!(result, Err(Error::NoAuth)));
    }

    #[tokio::test]
    async fn test_unknown_command() {
        let mut authenticated = true;
        let session_key = b"test_key".to_vec();
        let (db, _temp) = test_db();

        let args = vec![RespValue::BulkString(b"UNKNOWN".to_vec())];
        let value = RespValue::Array(args);

        let result = handle_command(value, &mut authenticated, &session_key, &db).await;

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
