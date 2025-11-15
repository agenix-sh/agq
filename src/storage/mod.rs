//! Storage layer for AGQ using redb embedded database
//!
//! Provides persistent storage for:
//! - Plans (JSON)
//! - Jobs (metadata, status, output)
//! - Queues (ready, scheduled)
//! - Workers (heartbeats, capabilities)

mod db;

pub use db::Database;

use crate::Result;

/// Storage operations for string (key-value) data
pub trait StringOps {
    /// Get a value by key
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Set a key-value pair
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn set(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Delete a key
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn del(&self, key: &str) -> Result<bool>;

    /// Check if a key exists
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn exists(&self, key: &str) -> Result<bool>;
}
