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
use async_trait::async_trait;

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
#[async_trait]
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
    async fn brpop(&self, key: &str, timeout_secs: u64) -> Result<Option<Vec<u8>>>;

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

    /// Atomically pop element from tail of source list and push to head of destination list
    ///
    /// # Arguments
    /// * `source` - The list key to pop from
    /// * `destination` - The list key to push to
    ///
    /// # Returns
    /// The element that was moved, or None if source list is empty
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    ///
    /// # Atomicity
    /// This operation is atomic - both pop and push occur in a single transaction.
    /// If either operation fails, neither occurs (transaction rollback).
    fn rpoplpush(&self, source: &str, destination: &str) -> Result<Option<Vec<u8>>>;

    /// Blocking version of rpoplpush - atomically pop from source and push to destination
    ///
    /// # Arguments
    /// * `source` - The list key to pop from
    /// * `destination` - The list key to push to
    /// * `timeout_secs` - Timeout in seconds (0 = block indefinitely)
    ///
    /// # Returns
    /// The element that was moved, or None if timeout occurs
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    ///
    /// # Atomicity
    /// This operation is atomic - both pop and push occur in a single transaction.
    /// Blocks until source list has elements or timeout occurs.
    async fn brpoplpush(
        &self,
        source: &str,
        destination: &str,
        timeout_secs: u64,
    ) -> Result<Option<Vec<u8>>>;
}

/// Storage operations for sorted set data
///
/// Sorted sets store members with associated scores, ordered by score.
/// Used for scheduling Jobs based on execution time.
pub trait SortedSetOps {
    /// Add a member with a score to a sorted set
    ///
    /// # Arguments
    /// * `key` - The sorted set key
    /// * `score` - The score (typically a Unix timestamp for scheduling)
    /// * `member` - The member value (typically a Job ID)
    ///
    /// # Returns
    /// Number of new elements added (0 if member already existed, 1 if new)
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn zadd(&self, key: &str, score: f64, member: &[u8]) -> Result<u64>;

    /// Get a range of members by index (sorted by score, low to high)
    ///
    /// # Arguments
    /// * `key` - The sorted set key
    /// * `start` - Start index (0-based, negative counts from end)
    /// * `stop` - Stop index (inclusive, negative counts from end)
    ///
    /// # Returns
    /// Vector of (member, score) tuples
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn zrange(&self, key: &str, start: i64, stop: i64) -> Result<Vec<(Vec<u8>, f64)>>;

    /// Get members by score range
    ///
    /// # Arguments
    /// * `key` - The sorted set key
    /// * `min_score` - Minimum score (inclusive)
    /// * `max_score` - Maximum score (inclusive)
    ///
    /// # Returns
    /// Vector of (member, score) tuples with scores in range [min_score, max_score]
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn zrangebyscore(
        &self,
        key: &str,
        min_score: f64,
        max_score: f64,
    ) -> Result<Vec<(Vec<u8>, f64)>>;

    /// Remove a member from a sorted set
    ///
    /// # Arguments
    /// * `key` - The sorted set key
    /// * `member` - The member to remove
    ///
    /// # Returns
    /// 1 if member was removed, 0 if member didn't exist
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn zrem(&self, key: &str, member: &[u8]) -> Result<u64>;

    /// Get the score of a member
    ///
    /// # Arguments
    /// * `key` - The sorted set key
    /// * `member` - The member to look up
    ///
    /// # Returns
    /// Some(score) if member exists, None otherwise
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn zscore(&self, key: &str, member: &[u8]) -> Result<Option<f64>>;

    /// Get the cardinality (number of members) of a sorted set
    ///
    /// # Arguments
    /// * `key` - The sorted set key
    ///
    /// # Returns
    /// Number of members in the sorted set
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn zcard(&self, key: &str) -> Result<u64>;
}

/// Storage operations for hash (field-value map) data
///
/// Hashes store field-value pairs within a key, enabling structured data storage.
/// Used for job metadata: job:<id> -> {status: "pending", stdout: "...", stderr: "..."}
pub trait HashOps {
    /// Set a field in a hash
    ///
    /// # Arguments
    /// * `key` - The hash key (e.g., "job:123")
    /// * `field` - The field name (e.g., "status")
    /// * `value` - The field value
    ///
    /// # Returns
    /// 1 if new field created, 0 if field updated
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn hset(&self, key: &str, field: &str, value: &[u8]) -> Result<u64>;

    /// Get a field value from a hash
    ///
    /// # Arguments
    /// * `key` - The hash key
    /// * `field` - The field name
    ///
    /// # Returns
    /// Some(value) if field exists, None otherwise
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn hget(&self, key: &str, field: &str) -> Result<Option<Vec<u8>>>;

    /// Delete a field from a hash
    ///
    /// # Arguments
    /// * `key` - The hash key
    /// * `field` - The field name
    ///
    /// # Returns
    /// 1 if field was deleted, 0 if field didn't exist
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn hdel(&self, key: &str, field: &str) -> Result<u64>;

    /// Get all field-value pairs from a hash
    ///
    /// # Arguments
    /// * `key` - The hash key
    ///
    /// # Returns
    /// Vector of (field, value) tuples
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn hgetall(&self, key: &str) -> Result<Vec<(String, Vec<u8>)>>;

    /// Check if a field exists in a hash
    ///
    /// # Arguments
    /// * `key` - The hash key
    /// * `field` - The field name
    ///
    /// # Returns
    /// true if field exists, false otherwise
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn hexists(&self, key: &str, field: &str) -> Result<bool>;

    /// Get the number of fields in a hash
    ///
    /// # Arguments
    /// * `key` - The hash key
    ///
    /// # Returns
    /// Number of fields in the hash
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn hlen(&self, key: &str) -> Result<u64>;
}
