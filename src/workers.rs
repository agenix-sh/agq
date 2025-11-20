//! Internal worker threads for processing queued operations
//!
//! Workers follow the internal queue worker pattern where RESP commands
//! push jobs to internal queues, and worker threads process them asynchronously.

use crate::error::{Error, Result};
use crate::storage::{Database, HashOps, ListOps, SortedSetOps};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

/// Internal job structure for queue-based operations
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InternalJob {
    /// Unique job ID
    pub id: String,
    /// Operation type (e.g., "plan.submit")
    pub operation: String,
    /// Entity ID (e.g., plan_id)
    pub entity_id: String,
    /// JSON payload
    pub payload: String,
    /// Unix timestamp when job was created
    pub timestamp: u64,
    /// Retry count
    pub retry_count: u32,
    /// Maximum retries allowed
    pub max_retries: u32,
}

/// Start the plan submission worker thread
///
/// This worker processes jobs from the `agq:internal:plan.submit` queue.
/// It runs in a background thread and processes plans asynchronously.
///
/// # Queue Pattern
/// Uses BRPOPLPUSH for reliability:
/// 1. Pop from `agq:internal:plan.submit`
/// 2. Push to `agq:internal:plan.submit:processing`
/// 3. Process the plan
/// 4. On success: remove from processing queue
/// 5. On failure: retry or move to DLQ
pub async fn start_plan_worker(db: Arc<Database>) {
    info!("Starting plan submission worker");

    loop {
        match process_plan_job(&db).await {
            Ok(true) => {
                // Processed a job successfully
                debug!("Plan job processed successfully");
            }
            Ok(false) => {
                // No job available (timeout)
                debug!("No plan jobs available, waiting...");
            }
            Err(e) => {
                error!("Error in plan worker: {}", e);
                // Sleep briefly to avoid tight error loops
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Process a single plan submission job
///
/// Returns Ok(true) if a job was processed, Ok(false) if timeout (no jobs available)
async fn process_plan_job(db: &Database) -> Result<bool> {
    // Use BRPOPLPUSH for reliability (30 second timeout)
    let job_data = db
        .brpoplpush(
            "agq:internal:plan.submit",
            "agq:internal:plan.submit:processing",
            30,
        )
        .await?;

    let Some(data) = job_data else {
        // Timeout - no jobs available
        return Ok(false);
    };

    // Deserialize job
    let job: InternalJob = serde_json::from_slice(&data)
        .map_err(|e| Error::Protocol(format!("Failed to deserialize internal job: {}", e)))?;

    debug!(
        "Processing plan job: {} (entity: {})",
        job.id, job.entity_id
    );

    // Process the plan storage
    match store_plan(&job, db).await {
        Ok(_) => {
            info!("Plan {} stored successfully", job.entity_id);

            // Success - remove from processing queue
            db.rpop("agq:internal:plan.submit:processing")?;

            Ok(true)
        }
        Err(e) => {
            error!("Failed to store plan {}: {}", job.entity_id, e);

            // Check if we should retry
            if job.retry_count < job.max_retries {
                // Retry - increment counter and push back to queue
                let mut retry_job = job.clone();
                retry_job.retry_count += 1;

                let retry_data = serde_json::to_vec(&retry_job).map_err(|e| {
                    Error::Protocol(format!("Failed to serialize retry job: {}", e))
                })?;

                // Remove from processing queue
                db.rpop("agq:internal:plan.submit:processing")?;

                // Push back to main queue for retry
                db.lpush("agq:internal:plan.submit", &retry_data)?;

                warn!(
                    "Plan {} failed, retrying ({}/{})",
                    job.entity_id, retry_job.retry_count, job.max_retries
                );
            } else {
                // Max retries exceeded - move to dead letter queue
                db.rpop("agq:internal:plan.submit:processing")?;
                db.lpush("agq:internal:plan.submit:dlq", &data)?;

                error!(
                    "Plan {} failed permanently after {} retries, moved to DLQ",
                    job.entity_id, job.max_retries
                );
            }

            Err(e)
        }
    }
}

/// Store a plan in the database
///
/// Creates:
/// - Hash: `plan:<id>` with fields: json, status, created_at, task_count, plan_description
/// - Sorted set: `plans:all` indexed by timestamp
async fn store_plan(job: &InternalJob, db: &Database) -> Result<()> {
    let plan_key = format!("plan:{}", job.entity_id);

    // Parse plan JSON to extract metadata (for efficient listing)
    let plan_value: serde_json::Value = serde_json::from_str(&job.payload)
        .map_err(|e| Error::Protocol(format!("Invalid plan JSON: {}", e)))?;

    let task_count = plan_value["tasks"]
        .as_array()
        .map(|tasks| tasks.len())
        .unwrap_or(0);

    let plan_description = plan_value["plan_description"].as_str().unwrap_or("");

    // Store plan hash with metadata
    db.hset(&plan_key, "json", job.payload.as_bytes())?;
    db.hset(&plan_key, "status", b"ready")?;
    db.hset(
        &plan_key,
        "created_at",
        job.timestamp.to_string().as_bytes(),
    )?;
    db.hset(&plan_key, "task_count", task_count.to_string().as_bytes())?;
    db.hset(&plan_key, "plan_description", plan_description.as_bytes())?;

    // Index plan in sorted set (for listing/discovery)
    db.zadd("plans:all", job.timestamp as f64, job.entity_id.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Database;
    use tempfile::TempDir;

    fn test_db() -> (Database, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let db = Database::open(&db_path).unwrap();
        (db, temp_dir)
    }

    #[tokio::test]
    async fn test_store_plan() {
        let (db, _temp) = test_db();

        let job = InternalJob {
            id: "job123".to_string(),
            operation: "plan.submit".to_string(),
            entity_id: "plan_test123".to_string(),
            payload: r#"{"plan_id":"plan_test123","tasks":[{"task_number":1,"command":"test"}]}"#
                .to_string(),
            timestamp: 1700000000,
            retry_count: 0,
            max_retries: 3,
        };

        store_plan(&job, &db).await.unwrap();

        // Verify plan hash was created
        let json = db.hget("plan:plan_test123", "json").unwrap().unwrap();
        assert_eq!(
            std::str::from_utf8(&json).unwrap(),
            r#"{"plan_id":"plan_test123","tasks":[{"task_number":1,"command":"test"}]}"#
        );

        let status = db.hget("plan:plan_test123", "status").unwrap().unwrap();
        assert_eq!(std::str::from_utf8(&status).unwrap(), "ready");

        // Verify plan was indexed
        let score = db.zscore("plans:all", b"plan_test123").unwrap();
        assert_eq!(score, Some(1700000000.0));
    }

    #[tokio::test]
    async fn test_process_plan_job_timeout() {
        let (db, _temp) = test_db();

        // Should return Ok(false) when no jobs available
        let result = process_plan_job(&db).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_process_plan_job_success() {
        let (db, _temp) = test_db();

        // Create a job
        let job = InternalJob {
            id: "job456".to_string(),
            operation: "plan.submit".to_string(),
            entity_id: "plan_test456".to_string(),
            payload: r#"{"plan_id":"plan_test456","tasks":[{"task_number":1,"command":"test"}]}"#
                .to_string(),
            timestamp: 1700000001,
            retry_count: 0,
            max_retries: 3,
        };

        let job_data = serde_json::to_vec(&job).unwrap();
        db.lpush("agq:internal:plan.submit", &job_data).unwrap();

        // Process the job
        let result = process_plan_job(&db).await.unwrap();
        assert!(result);

        // Verify plan was stored
        let json = db.hget("plan:plan_test456", "json").unwrap().unwrap();
        assert_eq!(
            std::str::from_utf8(&json).unwrap(),
            r#"{"plan_id":"plan_test456","tasks":[{"task_number":1,"command":"test"}]}"#
        );

        // Verify processing queue is empty
        let processing_len = db.llen("agq:internal:plan.submit:processing").unwrap();
        assert_eq!(processing_len, 0);
    }
}
