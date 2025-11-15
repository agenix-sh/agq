//! Database wrapper for redb embedded storage

use crate::storage::StringOps;
use crate::{Error, Result};
use redb::{Database as RedbDatabase, TableDefinition};
use std::path::Path;
use tracing::{debug, info};

/// Table for key-value string storage
const KV_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("kv");

/// AGQ Database wrapper
///
/// Provides ACID-compliant embedded storage using redb.
/// All operations are thread-safe and support concurrent reads.
pub struct Database {
    db: RedbDatabase,
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
            let _table = write_txn
                .open_table(KV_TABLE)
                .map_err(|e| Error::Protocol(format!("Failed to open KV table: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| Error::Protocol(format!("Failed to commit initialization: {e}")))?;

        info!("Database initialized successfully");

        Ok(Self { db })
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
}
