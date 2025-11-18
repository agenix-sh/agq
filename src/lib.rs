//! AGQ - Queue Manager for the AGX Agentic Ecosystem
//!
//! A minimal RESP server for handling Job queuing and worker coordination.
//! AGQ stores Plans, creates Jobs, and dispatches them to workers.

pub mod error;
pub mod resp;
pub mod server;
pub mod storage;
pub mod workers;

pub use error::{Error, Result};
pub use server::Server;
pub use storage::Database;
pub use workers::start_plan_worker;
