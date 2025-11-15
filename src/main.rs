//! AGQ - Queue Manager for the AGX Agentic Ecosystem
//!
//! Main entry point for the AGQ server.

use agq::{Result, Server};
use ring::rand::{SecureRandom, SystemRandom};
use tracing::{error, info};

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

    // Security: Generate secure session key
    // In Phase 1, this is a single static key
    // In production, this would be loaded from secure storage or per-session
    let session_key = generate_session_key()?;
    info!(
        "Generated session key (first 8 bytes): {:02x?}...",
        &session_key[..8.min(session_key.len())]
    );

    // Bind to localhost by default
    let addr = std::env::var("AGQ_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:6379".to_string());

    // Create and run server
    let server = Server::new(&addr, session_key).await?;
    info!("AGQ server started successfully");

    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        return Err(e);
    }

    Ok(())
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
