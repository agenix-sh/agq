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

/// Storage operations for list (queue) data
pub trait ListOps {
    /// Push element to the left (head) of a list
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn lpush(&self, key: &str, value: &[u8]) -> Result<u64>;

    /// Pop element from the right (tail) of a list
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn rpop(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Pop element from the right (tail) of a list, blocking until available or timeout
    ///
    /// # Arguments
    /// * `key` - The list key to pop from
    /// * `timeout_secs` - Timeout in seconds (0 = block indefinitely)
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn brpop(
        &self,
        key: &str,
        timeout_secs: u64,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> + Send;

    /// Get the length of a list
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn llen(&self, key: &str) -> Result<u64>;

    /// Get a range of elements from a list
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn lrange(&self, key: &str, start: i64, stop: i64) -> Result<Vec<Vec<u8>>>;
}
