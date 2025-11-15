//! AGQ - Queue Manager for the AGX Agentic Ecosystem
//!
//! A minimal RESP server for handling job queuing and worker coordination.

pub mod error;
pub mod resp;
pub mod server;
pub mod storage;

pub use error::{Error, Result};
pub use server::Server;
pub use storage::Database;
