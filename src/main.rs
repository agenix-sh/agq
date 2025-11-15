//! AGQ - Queue Manager for the AGX Agentic Ecosystem
//!
//! Main entry point for the AGQ server.

use agq::{Result, Server};
use clap::Parser;
use ring::rand::{SecureRandom, SystemRandom};
use tracing::{error, info, warn};

/// AGQ - Queue Manager for the AGX Agentic Ecosystem
///
/// Environment variables:
/// - `AGQ_BIND_ADDR`: Bind address (overridden by --bind)
/// - `AGQ_SESSION_KEY`: Session key (overridden by --session-key)
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Bind address (format: IP:PORT)
    #[arg(short, long, default_value = "127.0.0.1:6379")]
    bind: String,

    /// Session key for client authentication (hex-encoded)
    /// If not provided, a secure random key will be generated and displayed
    #[arg(short, long)]
    session_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting AGQ server v{}", env!("CARGO_PKG_VERSION"));

    // Parse command-line arguments
    let args = Args::parse();

    // Get bind address (CLI overrides env var, then default)
    let bind_addr = if args.bind != "127.0.0.1:6379" {
        // CLI arg was explicitly provided (different from default)
        args.bind
    } else if let Ok(addr) = std::env::var("AGQ_BIND_ADDR") {
        // Use env var if set
        addr
    } else {
        // Use default
        args.bind
    };

    // Get or generate session key (CLI overrides env var)
    let session_key = if let Some(key_hex) = args.session_key {
        // Use CLI-provided key
        parse_hex_key(&key_hex)?
    } else if let Ok(key_hex) = std::env::var("AGQ_SESSION_KEY") {
        // Use env var key
        parse_hex_key(&key_hex)?
    } else {
        // Generate secure session key
        let key = generate_session_key()?;
        let key_hex = hex::encode(&key);
        warn!("No session key provided - generated new key");
        warn!("Clients must authenticate with: AUTH {}", key_hex);
        warn!(
            "To reuse this key, restart with: --session-key {} or set AGQ_SESSION_KEY={}",
            key_hex, key_hex
        );
        key
    };

    // Create and run server
    let server = Server::new(&bind_addr, session_key).await?;
    info!("AGQ server started successfully on {}", bind_addr);

    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        return Err(e);
    }

    Ok(())
}

/// Parse hex-encoded session key
///
/// # Security
/// - Validates key length (must be at least 16 bytes)
/// - Validates hex encoding
///
/// # Errors
///
/// Returns an error if the key is invalid (not hex, too short, etc.)
fn parse_hex_key(hex_str: &str) -> Result<Vec<u8>> {
    let key = hex::decode(hex_str)
        .map_err(|_| agq::Error::InvalidArguments("Invalid hex-encoded session key".to_string()))?;

    if key.len() < 16 {
        return Err(agq::Error::InvalidArguments(
            "Session key must be at least 16 bytes (32 hex characters)".to_string(),
        ));
    }

    Ok(key)
}

/// Generate a cryptographically secure session key
///
/// # Security
/// Uses `ring` for secure random number generation
///
/// # Errors
///
/// Returns an error if the secure random number generation fails.
fn generate_session_key() -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut key = vec![0u8; 32]; // 256-bit key

    rng.fill(&mut key)
        .map_err(|_| agq::Error::Protocol("Failed to generate session key".to_string()))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_key_valid() {
        let key_hex = "0123456789abcdef0123456789abcdef";
        let result = parse_hex_key(key_hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_parse_hex_key_too_short() {
        let key_hex = "0123456789abcdef"; // Only 8 bytes
        let result = parse_hex_key(key_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hex_key_invalid_hex() {
        let key_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let result = parse_hex_key(key_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_session_key() {
        let result = generate_session_key();
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_parse_hex_key_256_bit() {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = parse_hex_key(key_hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }
}
