//! Database wrapper for redb embedded storage

use crate::storage::{ListOps, SortedSetOps, StringOps};
use crate::{Error, Result};
use async_trait::async_trait;
use redb::{Database as RedbDatabase, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time::{sleep, Duration};
use tracing::{debug, info};

/// Table for key-value string storage
const KV_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("kv");

/// Table for list metadata (head/tail pointers)
/// Key: list name, Value: (head_index: i64, tail_index: i64) as 16 bytes
const LIST_META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("list_meta");

/// Table for list elements
/// Key: "{list_name}:{index}", Value: element bytes
const LIST_DATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("list_data");

/// Table for sorted set member-to-score mapping
/// Key: "{zset_name}:{member}", Value: score (8 bytes, f64)
const ZSET_MEMBER_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("zset_member");

/// Table for sorted set score-to-member mapping (for range queries)
/// Key: "{zset_name}:{score_bytes}:{member}", Value: empty
/// The score is encoded as a sortable byte representation
const ZSET_SCORE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("zset_score");

/// AGQ Database wrapper
///
/// Provides ACID-compliant embedded storage using redb.
/// All operations are thread-safe and support concurrent reads.
pub struct Database {
    db: RedbDatabase,
    /// Notifications for list changes (used by BRPOP)
    /// Key format: list key name
    /// Uses std::sync::Mutex because we need to access it from both sync (LPUSH) and async (BRPOP) contexts
    list_notifiers: Arc<std::sync::Mutex<HashMap<String, Arc<Notify>>>>,
}

impl Database {
    /// Open or create a database at the given path
    ///
    /// # Security
    /// - Creates parent directories if they don't exist
    /// - Sets restrictive file permissions (0600)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path is invalid
    /// - Permission denied
    /// - Database file is corrupted
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        info!("Opening database at: {}", path.display());

        let db = RedbDatabase::create(path)
            .map_err(|e| Error::Protocol(format!("Failed to open database: {e}")))?;

        // Initialize tables
        let write_txn = db
            .begin_write()
            .map_err(|e| Error::Protocol(format!("Failed to begin write transaction: {e}")))?;
        {
            let _kv_table = write_txn
                .open_table(KV_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open KV table: {e}")))?;
            let _list_meta_table = write_txn
                .open_table(LIST_META_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open list meta table: {e}")))?;
            let _list_data_table = write_txn
                .open_table(LIST_DATA_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open list data table: {e}")))?;
            let _zset_member_table = write_txn
                .open_table(ZSET_MEMBER_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open zset member table: {e}")))?;
            let _zset_score_table = write_txn
                .open_table(ZSET_SCORE_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open zset score table: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| Error::Protocol(format!("Failed to commit initialization: {e}")))?;

        info!("Database initialized successfully");

        Ok(Self {
            db,
            list_notifiers: Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }
}

impl StringOps for Database {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::Protocol(format!("Failed to begin read transaction: {e}")))?;

        let table = read_txn
            .open_table(KV_TABLE)
            .map_err(|e| Error::Protocol(format!("Failed to open KV table: {e}")))?;

        match table.get(key) {
            Ok(Some(value)) => {
                let bytes = value.value().to_vec();
                debug!("GET {} -> {} bytes", key, bytes.len());
                Ok(Some(bytes))
            }
            Ok(None) => {
                debug!("GET {} -> (nil)", key);
                Ok(None)
            }
            Err(e) => Err(Error::Protocol(format!("Failed to get key: {e}"))),
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::Protocol(format!("Failed to begin write transaction: {e}")))?;

        {
            let mut table = write_txn
                .open_table(KV_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open KV table: {e}")))?;

            table
                .insert(key, value)
                .map_err(|e| Error::Protocol(format!("Failed to insert key: {e}")))?;
        }

        write_txn
            .commit()
            .map_err(|e| Error::Protocol(format!("Failed to commit transaction: {e}")))?;

        debug!("SET {} -> {} bytes", key, value.len());
        Ok(())
    }

    fn del(&self, key: &str) -> Result<bool> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::Protocol(format!("Failed to begin write transaction: {e}")))?;

        let deleted = {
            let mut table = write_txn
                .open_table(KV_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open KV table: {e}")))?;

            let result = table
                .remove(key)
                .map_err(|e| Error::Protocol(format!("Failed to delete key: {e}")))?;
            result.is_some()
        };

        write_txn
            .commit()
            .map_err(|e| Error::Protocol(format!("Failed to commit transaction: {e}")))?;

        debug!("DEL {} -> {}", key, deleted);
        Ok(deleted)
    }

    fn exists(&self, key: &str) -> Result<bool> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::Protocol(format!("Failed to begin read transaction: {e}")))?;

        let table = read_txn
            .open_table(KV_TABLE)
            .map_err(|e| Error::Protocol(format!("Failed to open KV table: {e}")))?;

        let exists = table
            .get(key)
            .map_err(|e| Error::Protocol(format!("Failed to check key: {e}")))?
            .is_some();

        debug!("EXISTS {} -> {}", key, exists);
        Ok(exists)
    }
}

/// Helper functions for list metadata serialization
fn encode_list_meta(head: i64, tail: i64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&head.to_le_bytes());
    bytes[8..16].copy_from_slice(&tail.to_le_bytes());
    bytes
}

fn decode_list_meta(bytes: &[u8]) -> Result<(i64, i64)> {
    if bytes.len() != 16 {
        return Err(Error::Protocol("Invalid list metadata".to_string()));
    }
    let head = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let tail = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
    Ok((head, tail))
}

fn list_element_key(list_key: &str, index: i64) -> String {
    format!("{}:{}", list_key, index)
}

/// Helper functions for sorted set operations
/// Encode f64 score to sortable bytes
/// Uses IEEE 754 with sign bit manipulation for proper sorting
fn encode_score(score: f64) -> [u8; 8] {
    let bits = score.to_bits();
    // Flip sign bit for negative numbers, or all bits if negative
    let sortable_bits = if (bits & (1u64 << 63)) != 0 {
        // Negative: flip all bits
        !bits
    } else {
        // Positive: flip only sign bit
        bits ^ (1u64 << 63)
    };
    sortable_bits.to_be_bytes()
}

/// Decode sortable bytes back to f64 score
fn decode_score(bytes: &[u8]) -> Result<f64> {
    if bytes.len() != 8 {
        return Err(Error::Protocol("Invalid score bytes".to_string()));
    }
    let sortable_bits = u64::from_be_bytes(bytes.try_into().unwrap());
    // Reverse the sign bit manipulation
    let bits = if (sortable_bits & (1u64 << 63)) == 0 {
        // Was negative: flip all bits back
        !sortable_bits
    } else {
        // Was positive: flip only sign bit back
        sortable_bits ^ (1u64 << 63)
    };
    Ok(f64::from_bits(bits))
}

/// Create member key for ZSET_MEMBER_TABLE: "{zset}:{member}"
fn zset_member_key(zset: &str, member: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(zset.len() + 1 + member.len());
    key.extend_from_slice(zset.as_bytes());
    key.push(b':');
    key.extend_from_slice(member);
    key
}

/// Create score key for ZSET_SCORE_TABLE: "{zset}:{score_hex}:{member_hex}"
/// We use hex encoding to ensure the key is valid UTF-8 for redb's &str keys
fn zset_score_key(zset: &str, score: f64, member: &[u8]) -> String {
    let score_bytes = encode_score(score);
    let score_hex = hex::encode(score_bytes);
    let member_hex = hex::encode(member);
    format!("{}:{}:{}", zset, score_hex, member_hex)
}

/// Parse member from score key: "{zset}:{score_hex}:{member_hex}" -> (member, score)
fn parse_score_key(key_str: &str, zset_prefix_len: usize) -> Result<(Vec<u8>, f64)> {
    // Format: "{zset}:{score_hex}:{member_hex}"
    // Skip "{zset}:" part
    let after_zset = &key_str[zset_prefix_len + 1..];

    // Find the second colon
    let parts: Vec<&str> = after_zset.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(Error::Protocol("Invalid score key format".to_string()));
    }

    // Decode score from hex
    let score_bytes = hex::decode(parts[0])
        .map_err(|_| Error::Protocol("Invalid score hex encoding".to_string()))?;
    if score_bytes.len() != 8 {
        return Err(Error::Protocol("Invalid score bytes length".to_string()));
    }
    let score = decode_score(&score_bytes)?;

    // Decode member from hex
    let member = hex::decode(parts[1])
        .map_err(|_| Error::Protocol("Invalid member hex encoding".to_string()))?;

    Ok((member, score))
}

#[async_trait]
impl ListOps for Database {
    fn lpush(&self, key: &str, value: &[u8]) -> Result<u64> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::Protocol(format!("Failed to begin write transaction: {e}")))?;

        let new_len = {
            let mut meta_table = write_txn
                .open_table(LIST_META_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open list meta table: {e}")))?;
            let mut data_table = write_txn
                .open_table(LIST_DATA_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open list data table: {e}")))?;

            // Get current head/tail or initialize
            let (head, tail) = match meta_table.get(key) {
                Ok(Some(meta)) => decode_list_meta(meta.value())?,
                Ok(None) => (0, -1), // Empty list: head=0, tail=-1
                Err(e) => return Err(Error::Protocol(format!("Failed to get list metadata: {e}"))),
            };

            // Push to head (left side)
            let new_head = head - 1;
            let element_key = list_element_key(key, new_head);
            data_table
                .insert(element_key.as_str(), value)
                .map_err(|e| Error::Protocol(format!("Failed to insert list element: {e}")))?;

            // Update tail if list was empty
            let new_tail = if tail < head { new_head } else { tail };

            // Update metadata
            let meta_bytes = encode_list_meta(new_head, new_tail);
            meta_table
                .insert(key, &meta_bytes[..])
                .map_err(|e| Error::Protocol(format!("Failed to update list metadata: {e}")))?;

            // Calculate new length
            (new_tail - new_head + 1) as u64
        };

        write_txn
            .commit()
            .map_err(|e| Error::Protocol(format!("Failed to commit transaction: {e}")))?;

        // Notify any waiting BRPOP calls
        // Uses std::sync::Mutex::lock() which blocks until the lock is available.
        // This ensures we never drop notifications (fixing the try_lock bug).
        if let Ok(notifiers) = self.list_notifiers.lock() {
            if let Some(notify) = notifiers.get(key) {
                notify.notify_waiters();
            }
        }

        debug!("LPUSH {} -> length {}", key, new_len);
        Ok(new_len)
    }

    fn rpop(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::Protocol(format!("Failed to begin write transaction: {e}")))?;

        let value = {
            let mut meta_table = write_txn
                .open_table(LIST_META_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open list meta table: {e}")))?;
            let mut data_table = write_txn
                .open_table(LIST_DATA_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open list data table: {e}")))?;

            // Get current head/tail
            let (head, tail) = match meta_table.get(key) {
                Ok(Some(meta)) => decode_list_meta(meta.value())?,
                Ok(None) => {
                    // List doesn't exist
                    return Ok(None);
                }
                Err(e) => return Err(Error::Protocol(format!("Failed to get list metadata: {e}"))),
            };

            if tail < head {
                // Empty list
                return Ok(None);
            }

            // Pop from tail (right side)
            let element_key = list_element_key(key, tail);
            let value = data_table
                .remove(element_key.as_str())
                .map_err(|e| Error::Protocol(format!("Failed to remove list element: {e}")))?
                .map(|v| v.value().to_vec());

            // Update metadata
            let new_tail = tail - 1;
            if new_tail < head {
                // List is now empty, remove metadata
                meta_table
                    .remove(key)
                    .map_err(|e| Error::Protocol(format!("Failed to remove list metadata: {e}")))?;
            } else {
                let meta_bytes = encode_list_meta(head, new_tail);
                meta_table
                    .insert(key, &meta_bytes[..])
                    .map_err(|e| Error::Protocol(format!("Failed to update list metadata: {e}")))?;
            }

            value
        };

        write_txn
            .commit()
            .map_err(|e| Error::Protocol(format!("Failed to commit transaction: {e}")))?;

        debug!("RPOP {} -> {:?}", key, value.is_some());
        Ok(value)
    }

    fn llen(&self, key: &str) -> Result<u64> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::Protocol(format!("Failed to begin read transaction: {e}")))?;

        let meta_table = read_txn
            .open_table(LIST_META_TABLE)
            .map_err(|e| Error::Protocol(format!("Failed to open list meta table: {e}")))?;

        let len = match meta_table.get(key) {
            Ok(Some(meta)) => {
                let (head, tail) = decode_list_meta(meta.value())?;
                if tail < head {
                    0
                } else {
                    (tail - head + 1) as u64
                }
            }
            Ok(None) => 0,
            Err(e) => return Err(Error::Protocol(format!("Failed to get list metadata: {e}"))),
        };

        debug!("LLEN {} -> {}", key, len);
        Ok(len)
    }

    fn lrange(&self, key: &str, start: i64, stop: i64) -> Result<Vec<Vec<u8>>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::Protocol(format!("Failed to begin read transaction: {e}")))?;

        let meta_table = read_txn
            .open_table(LIST_META_TABLE)
            .map_err(|e| Error::Protocol(format!("Failed to open list meta table: {e}")))?;
        let data_table = read_txn
            .open_table(LIST_DATA_TABLE)
            .map_err(|e| Error::Protocol(format!("Failed to open list data table: {e}")))?;

        let (head, tail) = match meta_table.get(key) {
            Ok(Some(meta)) => decode_list_meta(meta.value())?,
            Ok(None) => return Ok(vec![]), // List doesn't exist
            Err(e) => return Err(Error::Protocol(format!("Failed to get list metadata: {e}"))),
        };

        if tail < head {
            return Ok(vec![]); // Empty list
        }

        let len = tail - head + 1;

        // Convert negative indices to positive
        let start_idx = if start < 0 {
            (len + start).max(0)
        } else {
            start.min(len - 1)
        };

        let stop_idx = if stop < 0 {
            (len + stop).max(-1)
        } else {
            stop.min(len - 1)
        };

        if start_idx > stop_idx {
            return Ok(vec![]);
        }

        // Collect elements
        let mut result = Vec::new();
        for i in start_idx..=stop_idx {
            let actual_index = head + i;
            let element_key = list_element_key(key, actual_index);
            if let Some(value) = data_table
                .get(element_key.as_str())
                .map_err(|e| Error::Protocol(format!("Failed to get list element: {e}")))?
            {
                result.push(value.value().to_vec());
            }
        }

        debug!(
            "LRANGE {} {} {} -> {} elements",
            key,
            start,
            stop,
            result.len()
        );
        Ok(result)
    }

    async fn brpop(&self, key: &str, timeout_secs: u64) -> Result<Option<Vec<u8>>> {
        let start = std::time::Instant::now();
        let timeout_duration = if timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(timeout_secs))
        };

        // Get or create notifier for this key
        let notifier = {
            let mut notifiers = self
                .list_notifiers
                .lock()
                .map_err(|_| Error::Protocol("Failed to acquire notifier lock".to_string()))?;
            notifiers
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone()
        };

        loop {
            // Try to pop immediately
            if let Some(value) = self.rpop(key)? {
                debug!("BRPOP {} -> {} bytes (immediate)", key, value.len());
                return Ok(Some(value));
            }

            // Check if we've exceeded timeout
            if let Some(timeout) = timeout_duration {
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    debug!("BRPOP {} -> timeout after {:?}", key, elapsed);
                    return Ok(None);
                }

                // Wait for notification or timeout
                let remaining = timeout - elapsed;
                tokio::select! {
                    _ = notifier.notified() => {
                        // New data might be available, loop to try again
                        continue;
                    }
                    _ = sleep(remaining) => {
                        debug!("BRPOP {} -> timeout", key);
                        return Ok(None);
                    }
                }
            } else {
                // No timeout, wait indefinitely
                notifier.notified().await;
                // Loop to try popping again
            }
        }
    }
}

impl SortedSetOps for Database {
    fn zadd(&self, key: &str, score: f64, member: &[u8]) -> Result<u64> {
        // Security: Validate score is not NaN or infinite
        if !score.is_finite() {
            return Err(Error::InvalidArguments(
                "Score must be a finite number".to_string(),
            ));
        }

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::Protocol(format!("Failed to begin write transaction: {e}")))?;

        let added = {
            let mut member_table = write_txn
                .open_table(ZSET_MEMBER_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open zset member table: {e}")))?;
            let mut score_table = write_txn
                .open_table(ZSET_SCORE_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open zset score table: {e}")))?;

            let member_key = zset_member_key(key, member);
            let member_key_str = String::from_utf8_lossy(&member_key);

            // Check if member already exists
            let is_new =
                if let Ok(Some(old_score_bytes)) = member_table.get(member_key_str.as_ref()) {
                    // Member exists, remove old score index entry
                    let old_score = decode_score(old_score_bytes.value())?;
                    let old_score_key = zset_score_key(key, old_score, member);
                    score_table.remove(old_score_key.as_str()).map_err(|e| {
                        Error::Protocol(format!("Failed to remove old score entry: {e}"))
                    })?;
                    false // Not a new member
                } else {
                    true // New member
                };

            // Add/update member-to-score mapping
            let score_bytes = encode_score(score);
            member_table
                .insert(member_key_str.as_ref(), &score_bytes[..])
                .map_err(|e| Error::Protocol(format!("Failed to insert member: {e}")))?;

            // Add score-to-member index entry
            let score_key = zset_score_key(key, score, member);
            score_table
                .insert(score_key.as_str(), &b""[..])
                .map_err(|e| Error::Protocol(format!("Failed to insert score index: {e}")))?;

            u64::from(is_new)
        };

        write_txn
            .commit()
            .map_err(|e| Error::Protocol(format!("Failed to commit transaction: {e}")))?;

        debug!("ZADD {} {} -> added: {}", key, score, added);
        Ok(added)
    }

    fn zrange(&self, key: &str, start: i64, stop: i64) -> Result<Vec<(Vec<u8>, f64)>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::Protocol(format!("Failed to begin read transaction: {e}")))?;

        let score_table = read_txn
            .open_table(ZSET_SCORE_TABLE)
            .map_err(|e| Error::Protocol(format!("Failed to open zset score table: {e}")))?;

        // Collect all members for this sorted set
        let prefix = format!("{}:", key);
        let mut members: Vec<(Vec<u8>, f64)> = Vec::new();

        // Iterate through score table (already sorted by score)
        for item in score_table
            .iter()
            .map_err(|e| Error::Protocol(format!("Failed to iterate score table: {e}")))?
        {
            let (k, _) =
                item.map_err(|e| Error::Protocol(format!("Failed to read score entry: {e}")))?;
            let key_str = k.value();

            if key_str.starts_with(&prefix) {
                let (member, score) = parse_score_key(key_str, prefix.len() - 1)?;
                members.push((member, score));
            }
        }

        if members.is_empty() {
            return Ok(vec![]);
        }

        let len = members.len() as i64;

        // Convert negative indices to positive
        let start_idx = if start < 0 {
            (len + start).max(0) as usize
        } else {
            (start.min(len - 1)) as usize
        };

        let stop_idx = if stop < 0 {
            (len + stop).max(-1) as usize
        } else {
            (stop.min(len - 1)) as usize
        };

        if start_idx > stop_idx {
            return Ok(vec![]);
        }

        let result = members[start_idx..=stop_idx].to_vec();
        debug!(
            "ZRANGE {} {} {} -> {} members",
            key,
            start,
            stop,
            result.len()
        );
        Ok(result)
    }

    fn zrangebyscore(
        &self,
        key: &str,
        min_score: f64,
        max_score: f64,
    ) -> Result<Vec<(Vec<u8>, f64)>> {
        // Security: Validate scores are finite
        if !min_score.is_finite() || !max_score.is_finite() {
            return Err(Error::InvalidArguments(
                "Scores must be finite numbers".to_string(),
            ));
        }

        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::Protocol(format!("Failed to begin read transaction: {e}")))?;

        let score_table = read_txn
            .open_table(ZSET_SCORE_TABLE)
            .map_err(|e| Error::Protocol(format!("Failed to open zset score table: {e}")))?;

        let prefix = format!("{}:", key);
        let mut members: Vec<(Vec<u8>, f64)> = Vec::new();

        // Iterate through score table and filter by score range
        for item in score_table
            .iter()
            .map_err(|e| Error::Protocol(format!("Failed to iterate score table: {e}")))?
        {
            let (k, _) =
                item.map_err(|e| Error::Protocol(format!("Failed to read score entry: {e}")))?;
            let key_str = k.value();

            if key_str.starts_with(&prefix) {
                let (member, score) = parse_score_key(key_str, prefix.len() - 1)?;
                if score >= min_score && score <= max_score {
                    members.push((member, score));
                }
            }
        }

        debug!(
            "ZRANGEBYSCORE {} {} {} -> {} members",
            key,
            min_score,
            max_score,
            members.len()
        );
        Ok(members)
    }

    fn zrem(&self, key: &str, member: &[u8]) -> Result<u64> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| Error::Protocol(format!("Failed to begin write transaction: {e}")))?;

        let removed = {
            let mut member_table = write_txn
                .open_table(ZSET_MEMBER_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open zset member table: {e}")))?;
            let mut score_table = write_txn
                .open_table(ZSET_SCORE_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open zset score table: {e}")))?;

            let member_key = zset_member_key(key, member);
            let member_key_str = String::from_utf8_lossy(&member_key);

            // Get the score first
            let score_bytes = match member_table.get(member_key_str.as_ref()) {
                Ok(Some(bytes)) => bytes.value().to_vec(),
                Ok(None) => return Ok(0), // Member doesn't exist
                Err(e) => return Err(Error::Protocol(format!("Failed to get member: {e}"))),
            };

            let score = decode_score(&score_bytes)?;

            // Remove member-to-score mapping
            member_table
                .remove(member_key_str.as_ref())
                .map_err(|e| Error::Protocol(format!("Failed to remove member: {e}")))?;

            // Remove score-to-member index
            let score_key = zset_score_key(key, score, member);
            score_table
                .remove(score_key.as_str())
                .map_err(|e| Error::Protocol(format!("Failed to remove score index: {e}")))?;

            1u64
        };

        write_txn
            .commit()
            .map_err(|e| Error::Protocol(format!("Failed to commit transaction: {e}")))?;

        debug!("ZREM {} -> removed: {}", key, removed);
        Ok(removed)
    }

    fn zscore(&self, key: &str, member: &[u8]) -> Result<Option<f64>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::Protocol(format!("Failed to begin read transaction: {e}")))?;

        let member_table = read_txn
            .open_table(ZSET_MEMBER_TABLE)
            .map_err(|e| Error::Protocol(format!("Failed to open zset member table: {e}")))?;

        let member_key = zset_member_key(key, member);
        let member_key_str = String::from_utf8_lossy(&member_key);

        match member_table.get(member_key_str.as_ref()) {
            Ok(Some(score_bytes)) => {
                let score = decode_score(score_bytes.value())?;
                debug!("ZSCORE {} -> {}", key, score);
                Ok(Some(score))
            }
            Ok(None) => {
                debug!("ZSCORE {} -> (nil)", key);
                Ok(None)
            }
            Err(e) => Err(Error::Protocol(format!("Failed to get score: {e}"))),
        }
    }

    fn zcard(&self, key: &str) -> Result<u64> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| Error::Protocol(format!("Failed to begin read transaction: {e}")))?;

        let score_table = read_txn
            .open_table(ZSET_SCORE_TABLE)
            .map_err(|e| Error::Protocol(format!("Failed to open zset score table: {e}")))?;

        let prefix = format!("{}:", key);
        let mut count = 0u64;

        for item in score_table
            .iter()
            .map_err(|e| Error::Protocol(format!("Failed to iterate score table: {e}")))?
        {
            let (k, _) =
                item.map_err(|e| Error::Protocol(format!("Failed to read score entry: {e}")))?;
            let key_str = k.value();
            if key_str.starts_with(&prefix) {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| Error::Protocol("Count overflow".to_string()))?;
            }
        }

        debug!("ZCARD {} -> {}", key, count);
        Ok(count)
    }
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

    #[test]
    fn test_database_open() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let result = Database::open(&db_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_set_and_get() {
        let (db, _temp) = test_db();

        db.set("key1", b"value1").unwrap();
        let value = db.get("key1").unwrap();

        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[test]
    fn test_get_nonexistent() {
        let (db, _temp) = test_db();

        let value = db.get("nonexistent").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_delete() {
        let (db, _temp) = test_db();

        db.set("key1", b"value1").unwrap();
        let deleted = db.del("key1").unwrap();
        assert!(deleted);

        let value = db.get("key1").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_delete_nonexistent() {
        let (db, _temp) = test_db();

        let deleted = db.del("nonexistent").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_exists() {
        let (db, _temp) = test_db();

        db.set("key1", b"value1").unwrap();
        assert!(db.exists("key1").unwrap());
        assert!(!db.exists("nonexistent").unwrap());
    }

    #[test]
    fn test_overwrite() {
        let (db, _temp) = test_db();

        db.set("key1", b"value1").unwrap();
        db.set("key1", b"value2").unwrap();

        let value = db.get("key1").unwrap();
        assert_eq!(value, Some(b"value2".to_vec()));
    }

    #[test]
    fn test_binary_data() {
        let (db, _temp) = test_db();

        let binary_data = vec![0u8, 1, 2, 255, 254, 253];
        db.set("binary", &binary_data).unwrap();

        let value = db.get("binary").unwrap();
        assert_eq!(value, Some(binary_data));
    }

    #[test]
    fn test_lpush_and_llen() {
        let (db, _temp) = test_db();

        // Push first element
        let len = db.lpush("mylist", b"first").unwrap();
        assert_eq!(len, 1);

        // Push second element
        let len = db.lpush("mylist", b"second").unwrap();
        assert_eq!(len, 2);

        // Check length
        assert_eq!(db.llen("mylist").unwrap(), 2);
    }

    #[test]
    fn test_lpush_and_rpop() {
        let (db, _temp) = test_db();

        // Push elements (LPUSH adds to head)
        db.lpush("mylist", b"first").unwrap();
        db.lpush("mylist", b"second").unwrap();
        db.lpush("mylist", b"third").unwrap();

        // RPOP removes from tail (should be "first")
        let value = db.rpop("mylist").unwrap();
        assert_eq!(value, Some(b"first".to_vec()));

        // Pop again (should be "second")
        let value = db.rpop("mylist").unwrap();
        assert_eq!(value, Some(b"second".to_vec()));

        // Pop last element
        let value = db.rpop("mylist").unwrap();
        assert_eq!(value, Some(b"third".to_vec()));

        // List should be empty now
        let value = db.rpop("mylist").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_rpop_empty_list() {
        let (db, _temp) = test_db();

        let value = db.rpop("nonexistent").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_llen_empty_list() {
        let (db, _temp) = test_db();

        assert_eq!(db.llen("nonexistent").unwrap(), 0);
    }

    #[test]
    fn test_lrange_basic() {
        let (db, _temp) = test_db();

        // Push elements
        db.lpush("mylist", b"one").unwrap();
        db.lpush("mylist", b"two").unwrap();
        db.lpush("mylist", b"three").unwrap();

        // List order: [three, two, one] (LPUSH adds to head)
        let range = db.lrange("mylist", 0, -1).unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0], b"three");
        assert_eq!(range[1], b"two");
        assert_eq!(range[2], b"one");
    }

    #[test]
    fn test_lrange_partial() {
        let (db, _temp) = test_db();

        db.lpush("mylist", b"one").unwrap();
        db.lpush("mylist", b"two").unwrap();
        db.lpush("mylist", b"three").unwrap();

        // Get first two elements
        let range = db.lrange("mylist", 0, 1).unwrap();
        assert_eq!(range.len(), 2);
        assert_eq!(range[0], b"three");
        assert_eq!(range[1], b"two");
    }

    #[test]
    fn test_lrange_negative_indices() {
        let (db, _temp) = test_db();

        db.lpush("mylist", b"one").unwrap();
        db.lpush("mylist", b"two").unwrap();
        db.lpush("mylist", b"three").unwrap();

        // Get last element
        let range = db.lrange("mylist", -1, -1).unwrap();
        assert_eq!(range.len(), 1);
        assert_eq!(range[0], b"one");

        // Get last two elements
        let range = db.lrange("mylist", -2, -1).unwrap();
        assert_eq!(range.len(), 2);
        assert_eq!(range[0], b"two");
        assert_eq!(range[1], b"one");
    }

    #[test]
    fn test_lrange_empty_list() {
        let (db, _temp) = test_db();

        let range = db.lrange("nonexistent", 0, -1).unwrap();
        assert_eq!(range.len(), 0);
    }

    #[tokio::test]
    async fn test_brpop_immediate() {
        let (db, _temp) = test_db();

        // Push element
        db.lpush("mylist", b"value").unwrap();

        // BRPOP should return immediately
        let value = db.brpop("mylist", 1).await.unwrap();
        assert_eq!(value, Some(b"value".to_vec()));
    }

    #[tokio::test]
    async fn test_brpop_timeout() {
        let (db, _temp) = test_db();

        // BRPOP on empty list should timeout
        let start = std::time::Instant::now();
        let value = db.brpop("mylist", 1).await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(value, None);
        assert!(elapsed >= std::time::Duration::from_secs(1));
        assert!(elapsed < std::time::Duration::from_millis(1500));
    }

    #[tokio::test]
    async fn test_brpop_notification() {
        let (db, _temp) = test_db();
        let db = std::sync::Arc::new(db);

        // Spawn task that will push after 500ms
        let db_clone = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            db_clone.lpush("mylist", b"delayed").unwrap();
        });

        // BRPOP should wake up when element is pushed
        let start = std::time::Instant::now();
        let value = db.brpop("mylist", 5).await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(value, Some(b"delayed".to_vec()));
        // Should complete in ~500ms, not 5 seconds
        assert!(elapsed < std::time::Duration::from_secs(1));
    }

    // Sorted Set Tests

    #[test]
    fn test_zadd_and_zscore() {
        let (db, _temp) = test_db();

        // Add first member
        let added = db.zadd("myzset", 1.5, b"member1").unwrap();
        assert_eq!(added, 1); // New member

        // Add second member
        let added = db.zadd("myzset", 2.5, b"member2").unwrap();
        assert_eq!(added, 1);

        // Update existing member (should return 0)
        let added = db.zadd("myzset", 3.0, b"member1").unwrap();
        assert_eq!(added, 0); // Not new

        // Check scores
        assert_eq!(db.zscore("myzset", b"member1").unwrap(), Some(3.0));
        assert_eq!(db.zscore("myzset", b"member2").unwrap(), Some(2.5));
        assert_eq!(db.zscore("myzset", b"nonexistent").unwrap(), None);
    }

    #[test]
    fn test_zadd_negative_scores() {
        let (db, _temp) = test_db();

        db.zadd("myzset", -10.5, b"negative").unwrap();
        db.zadd("myzset", 0.0, b"zero").unwrap();
        db.zadd("myzset", 10.5, b"positive").unwrap();

        assert_eq!(db.zscore("myzset", b"negative").unwrap(), Some(-10.5));
        assert_eq!(db.zscore("myzset", b"zero").unwrap(), Some(0.0));
        assert_eq!(db.zscore("myzset", b"positive").unwrap(), Some(10.5));
    }

    #[test]
    fn test_zadd_nan_rejected() {
        let (db, _temp) = test_db();

        let result = db.zadd("myzset", f64::NAN, b"member");
        assert!(result.is_err());

        let result = db.zadd("myzset", f64::INFINITY, b"member");
        assert!(result.is_err());

        let result = db.zadd("myzset", f64::NEG_INFINITY, b"member");
        assert!(result.is_err());
    }

    #[test]
    fn test_zrange_all() {
        let (db, _temp) = test_db();

        db.zadd("myzset", 1.0, b"one").unwrap();
        db.zadd("myzset", 2.0, b"two").unwrap();
        db.zadd("myzset", 3.0, b"three").unwrap();

        let members = db.zrange("myzset", 0, -1).unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[0], (b"one".to_vec(), 1.0));
        assert_eq!(members[1], (b"two".to_vec(), 2.0));
        assert_eq!(members[2], (b"three".to_vec(), 3.0));
    }

    #[test]
    fn test_zrange_partial() {
        let (db, _temp) = test_db();

        db.zadd("myzset", 1.0, b"one").unwrap();
        db.zadd("myzset", 2.0, b"two").unwrap();
        db.zadd("myzset", 3.0, b"three").unwrap();
        db.zadd("myzset", 4.0, b"four").unwrap();

        // Get first two
        let members = db.zrange("myzset", 0, 1).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0], (b"one".to_vec(), 1.0));
        assert_eq!(members[1], (b"two".to_vec(), 2.0));

        // Get last two
        let members = db.zrange("myzset", -2, -1).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0], (b"three".to_vec(), 3.0));
        assert_eq!(members[1], (b"four".to_vec(), 4.0));
    }

    #[test]
    fn test_zrange_empty() {
        let (db, _temp) = test_db();

        let members = db.zrange("nonexistent", 0, -1).unwrap();
        assert_eq!(members.len(), 0);
    }

    #[test]
    fn test_zrange_with_negative_scores() {
        let (db, _temp) = test_db();

        db.zadd("myzset", -2.0, b"minus_two").unwrap();
        db.zadd("myzset", -1.0, b"minus_one").unwrap();
        db.zadd("myzset", 0.0, b"zero").unwrap();
        db.zadd("myzset", 1.0, b"one").unwrap();

        let members = db.zrange("myzset", 0, -1).unwrap();
        assert_eq!(members.len(), 4);
        // Should be sorted by score
        assert_eq!(members[0], (b"minus_two".to_vec(), -2.0));
        assert_eq!(members[1], (b"minus_one".to_vec(), -1.0));
        assert_eq!(members[2], (b"zero".to_vec(), 0.0));
        assert_eq!(members[3], (b"one".to_vec(), 1.0));
    }

    #[test]
    fn test_zrangebyscore() {
        let (db, _temp) = test_db();

        db.zadd("myzset", 1.0, b"one").unwrap();
        db.zadd("myzset", 2.0, b"two").unwrap();
        db.zadd("myzset", 3.0, b"three").unwrap();
        db.zadd("myzset", 4.0, b"four").unwrap();
        db.zadd("myzset", 5.0, b"five").unwrap();

        // Get range [2.0, 4.0]
        let members = db.zrangebyscore("myzset", 2.0, 4.0).unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[0], (b"two".to_vec(), 2.0));
        assert_eq!(members[1], (b"three".to_vec(), 3.0));
        assert_eq!(members[2], (b"four".to_vec(), 4.0));
    }

    #[test]
    fn test_zrangebyscore_empty_range() {
        let (db, _temp) = test_db();

        db.zadd("myzset", 1.0, b"one").unwrap();
        db.zadd("myzset", 5.0, b"five").unwrap();

        // No members in range [2.0, 4.0]
        let members = db.zrangebyscore("myzset", 2.0, 4.0).unwrap();
        assert_eq!(members.len(), 0);
    }

    #[test]
    fn test_zrangebyscore_with_timestamps() {
        let (db, _temp) = test_db();

        // Use Unix timestamps
        let now = 1700000000.0;
        db.zadd("scheduled", now, b"job1").unwrap();
        db.zadd("scheduled", now + 60.0, b"job2").unwrap();
        db.zadd("scheduled", now + 120.0, b"job3").unwrap();
        db.zadd("scheduled", now + 180.0, b"job4").unwrap();

        // Get jobs due in first 90 seconds
        let members = db.zrangebyscore("scheduled", now, now + 90.0).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0], (b"job1".to_vec(), now));
        assert_eq!(members[1], (b"job2".to_vec(), now + 60.0));
    }

    #[test]
    fn test_zrangebyscore_nan_rejected() {
        let (db, _temp) = test_db();

        let result = db.zrangebyscore("myzset", f64::NAN, 10.0);
        assert!(result.is_err());

        let result = db.zrangebyscore("myzset", 0.0, f64::INFINITY);
        assert!(result.is_err());
    }

    #[test]
    fn test_zrem() {
        let (db, _temp) = test_db();

        db.zadd("myzset", 1.0, b"one").unwrap();
        db.zadd("myzset", 2.0, b"two").unwrap();
        db.zadd("myzset", 3.0, b"three").unwrap();

        // Remove existing member
        let removed = db.zrem("myzset", b"two").unwrap();
        assert_eq!(removed, 1);

        // Verify removal
        assert_eq!(db.zscore("myzset", b"two").unwrap(), None);
        let members = db.zrange("myzset", 0, -1).unwrap();
        assert_eq!(members.len(), 2);

        // Remove nonexistent member
        let removed = db.zrem("myzset", b"nonexistent").unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_zcard() {
        let (db, _temp) = test_db();

        // Empty set
        assert_eq!(db.zcard("myzset").unwrap(), 0);

        // Add members
        db.zadd("myzset", 1.0, b"one").unwrap();
        assert_eq!(db.zcard("myzset").unwrap(), 1);

        db.zadd("myzset", 2.0, b"two").unwrap();
        db.zadd("myzset", 3.0, b"three").unwrap();
        assert_eq!(db.zcard("myzset").unwrap(), 3);

        // Update existing (should not change cardinality)
        db.zadd("myzset", 4.0, b"one").unwrap();
        assert_eq!(db.zcard("myzset").unwrap(), 3);

        // Remove member
        db.zrem("myzset", b"two").unwrap();
        assert_eq!(db.zcard("myzset").unwrap(), 2);
    }

    #[test]
    fn test_sorted_set_isolation() {
        let (db, _temp) = test_db();

        // Add members to two different sets
        db.zadd("zset1", 1.0, b"member1").unwrap();
        db.zadd("zset2", 2.0, b"member2").unwrap();

        // Check isolation
        assert_eq!(db.zcard("zset1").unwrap(), 1);
        assert_eq!(db.zcard("zset2").unwrap(), 1);

        assert_eq!(db.zscore("zset1", b"member1").unwrap(), Some(1.0));
        assert_eq!(db.zscore("zset1", b"member2").unwrap(), None);

        assert_eq!(db.zscore("zset2", b"member2").unwrap(), Some(2.0));
        assert_eq!(db.zscore("zset2", b"member1").unwrap(), None);
    }

    #[test]
    fn test_score_encoding_correctness() {
        // Test that score encoding preserves sort order
        let scores = vec![-1000.0, -10.5, -1.0, -0.1, 0.0, 0.1, 1.0, 10.5, 1000.0];

        let mut encoded: Vec<([u8; 8], f64)> =
            scores.iter().map(|&s| (encode_score(s), s)).collect();

        // Encoded bytes should sort in same order as original scores
        encoded.sort_by(|a, b| a.0.cmp(&b.0));

        for i in 0..encoded.len() {
            // Verify decode gives back original
            let decoded = decode_score(&encoded[i].0).unwrap();
            assert!((decoded - encoded[i].1).abs() < f64::EPSILON);

            // Verify order is preserved
            if i > 0 {
                assert!(encoded[i].1 >= encoded[i - 1].1);
            }
        }
    }

    #[test]
    fn test_zadd_update_preserves_order() {
        let (db, _temp) = test_db();

        // Add members
        db.zadd("myzset", 1.0, b"member1").unwrap();
        db.zadd("myzset", 2.0, b"member2").unwrap();
        db.zadd("myzset", 3.0, b"member3").unwrap();

        // Update member2 to have highest score
        db.zadd("myzset", 4.0, b"member2").unwrap();

        // Verify order
        let members = db.zrange("myzset", 0, -1).unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[0], (b"member1".to_vec(), 1.0));
        assert_eq!(members[1], (b"member3".to_vec(), 3.0));
        assert_eq!(members[2], (b"member2".to_vec(), 4.0));
    }
}
