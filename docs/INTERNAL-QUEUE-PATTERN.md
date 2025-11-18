# Internal Queue Worker Pattern

**Status**: Design Document
**Version**: 0.1
**Date**: 2025-11-18

## Overview

AGQ uses an **internal queue worker pattern** for asynchronous operations triggered by RESP commands. This provides a unified, composable architecture where external commands (from AGX) trigger internal jobs processed by AGQ worker threads.

## Architecture

### Principle: Everything is a Queue

```
┌─────────────────────────────────────────────────────────┐
│  AGX (External Client)                                  │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼ RESP Command (e.g., PLAN.SUBMIT)
┌─────────────────────────────────────────────────────────┐
│  AGQ - Command Handler Layer                            │
│  ┌──────────────────────────────────────────┐          │
│  │ 1. Validate input                        │          │
│  │ 2. Generate ID (plan_id, action_id, etc)│          │
│  │ 3. LPUSH to internal queue               │          │
│  │ 4. Return ID immediately (async)         │          │
│  └──────────────────────────────────────────┘          │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼ Internal Queue (agq:internal:*)
┌─────────────────────────────────────────────────────────┐
│  AGQ - Internal Worker Thread                           │
│  ┌──────────────────────────────────────────┐          │
│  │ 1. BRPOP from internal queue             │          │
│  │ 2. Process operation                     │          │
│  │ 3. Update storage/state                  │          │
│  │ 4. Handle errors/retries                 │          │
│  └──────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────┘
```

## Benefits

### 1. Unified Interface
- AGX only knows: "submit to queue via RESP command"
- All operations use the same pattern
- No special-case client logic

### 2. Composability
- Same mechanism for all asynchronous operations
- Easy to add new operation types
- Internal workers can chain operations

### 3. Reliability
- Automatic retry via RPOPLPUSH to processing queue
- Crash recovery (items remain in queue)
- Audit trail (every operation is a job)

### 4. Scalability
- Multiple internal workers can process in parallel
- Natural backpressure from queue depth
- Can prioritize queues

### 5. Future-Proof
- Plan transformations
- Action fan-out
- Workflow orchestration
- All use the same pattern

## Internal Queue Naming Convention

```
agq:internal:<entity>.<operation>
```

**Examples:**
- `agq:internal:plan.submit` - Plans to be stored
- `agq:internal:action.schedule` - Actions to fan out into Jobs
- `agq:internal:workflow.step` - Workflow state machine transitions
- `agq:internal:plan.version` - Plan versioning operations

**Processing queues** (for RPOPLPUSH pattern):
- `agq:internal:plan.submit:processing`
- `agq:internal:action.schedule:processing`

## Command Pattern: `.SUBMIT` Commands

All `.SUBMIT` commands follow this pattern:

### 1. Command Handler (Synchronous)

```rust
async fn handle_plan_submit(args: &[RespValue], db: &Database) -> Result<RespValue> {
    // 1. Validate input
    let plan_json = args[1].as_string()?;
    validate_plan_schema(plan_json)?;

    // 2. Generate ID
    let plan_id = generate_plan_id();

    // 3. Create internal job
    let internal_job = InternalJob {
        id: Uuid::new_v4(),
        operation: "plan.submit",
        plan_id: plan_id.clone(),
        payload: plan_json.to_string(),
        timestamp: now(),
    };

    // 4. Push to internal queue
    db.lpush("agq:internal:plan.submit", &serde_json::to_vec(&internal_job)?)?;

    // 5. Return ID immediately (operation continues asynchronously)
    Ok(RespValue::SimpleString(plan_id))
}
```

### 2. Internal Worker (Asynchronous)

```rust
async fn internal_worker_loop(db: Database) {
    loop {
        // Use BRPOPLPUSH for reliability
        let job_data = db.brpoplpush(
            "agq:internal:plan.submit",
            "agq:internal:plan.submit:processing",
            30, // 30 second timeout
        ).await;

        if let Some(data) = job_data {
            match process_plan_submit(&data, &db).await {
                Ok(_) => {
                    // Success - remove from processing queue
                    db.rpop("agq:internal:plan.submit:processing");
                }
                Err(e) => {
                    // Error - handle retry logic
                    handle_internal_job_error(&data, e, &db).await;
                }
            }
        }
    }
}

async fn process_plan_submit(job_data: &[u8], db: &Database) -> Result<()> {
    let job: InternalJob = serde_json::from_slice(job_data)?;

    // 1. Parse plan
    let plan: Plan = serde_json::from_str(&job.payload)?;

    // 2. Store plan
    db.hset(&format!("plan:{}", job.plan_id), "json", job.payload.as_bytes())?;
    db.hset(&format!("plan:{}", job.plan_id), "status", b"ready")?;
    db.hset(&format!("plan:{}", job.plan_id), "created_at", &job.timestamp.to_string())?;

    // 3. Index plan (for search/discovery)
    db.zadd("plans:all", job.timestamp as f64, job.plan_id.as_bytes())?;

    Ok(())
}
```

## Internal Job Structure

```json
{
  "id": "uuid-v4",
  "operation": "plan.submit",
  "entity_id": "plan_abc123",
  "payload": "{...json...}",
  "timestamp": 1700000000,
  "retry_count": 0,
  "max_retries": 3
}
```

## Queue Lifecycle

```
┌──────────────────────┐
│  PLAN.SUBMIT command │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────────┐
│ agq:internal:plan.submit     │  (ready queue)
│ [job1, job2, job3]           │
└──────────┬───────────────────┘
           │ BRPOPLPUSH
           ▼
┌──────────────────────────────────────┐
│ agq:internal:plan.submit:processing  │  (processing queue)
│ [job1]                               │
└──────────┬───────────────────────────┘
           │ Success: RPOP
           │ Failure: LPUSH to retry queue
           ▼
┌────────────────────┐        ┌─────────────────────────┐
│  Plan stored ✓     │        │ agq:internal:plan.retry │
│  Status: ready     │        │ [failed_job]            │
└────────────────────┘        └─────────────────────────┘
```

## Implementation Checklist

For each new `.SUBMIT` command:

- [ ] Define RESP command (e.g., `PLAN.SUBMIT`)
- [ ] Add command handler with validation
- [ ] Define internal queue name
- [ ] Create InternalJob structure
- [ ] Implement internal worker function
- [ ] Add storage operations
- [ ] Implement error handling and retry logic
- [ ] Add monitoring/logging
- [ ] Write integration tests
- [ ] Document command in API docs

## Security Considerations

### Input Validation
- Validate JSON schema before queuing
- Size limits on payloads (prevent resource exhaustion)
- Rate limiting on submission commands

### Resource Protection
- Maximum queue depth limits
- Worker thread limits
- Timeout on processing operations

### Isolation
- Internal queues are NOT accessible via external RESP commands
- Only AGQ code can interact with `agq:internal:*` queues
- Separate from user-facing job queues

## Future Extensions

### Multi-Step Workflows
Internal workers can chain operations:

```
PLAN.SUBMIT → plan.submit queue
              ↓
              Internal Worker 1: Store plan
              ↓
              LPUSH to action.schedule queue
              ↓
              Internal Worker 2: Fan out actions
              ↓
              Create multiple Jobs in user queues
```

### Priority Queues
```
agq:internal:plan.submit:high
agq:internal:plan.submit:normal
agq:internal:plan.submit:low
```

### Workflow State Machine
```
agq:internal:workflow.step
→ Worker evaluates conditions
→ LPUSH to next step queue
```

## Examples of .SUBMIT Commands

### Current (AGQ-009)
- `PLAN.SUBMIT <plan_json>` → Returns `plan_id`

### Future
- `ACTION.SUBMIT <plan_id> <inputs_json>` → Returns `action_id`
  - Internal worker fans out into multiple Jobs

- `WORKFLOW.SUBMIT <workflow_json>` → Returns `workflow_id`
  - Internal worker manages state machine

- `PLAN.VERSION <plan_id> <updated_json>` → Returns `version_id`
  - Internal worker creates new version with lineage

## References

- EXECUTION-LAYERS.md - Canonical nomenclature (Plan/Job/Action/Workflow)
- ARCHITECTURE.md - Overall AGQ design
- ROADMAP.md - Future enhancements

---

**Pattern established**: AGQ-009 (PLAN.SUBMIT)
**Applies to**: AGQ-014, AGQ-015 (Plan storage/versioning), Future workflow commands
