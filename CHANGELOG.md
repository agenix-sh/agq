# Changelog

All notable changes to AGQ will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed - ⚠️ BREAKING CHANGES

#### Job Schema Refactoring (#46)
**Impact:** Workers (AGW) must be updated to handle new job format

**What Changed:**
- Jobs now reference `plan_id` instead of embedding full plan
- Job JSON no longer contains `tasks` array
- Workers must fetch plans separately using `PLAN.GET`

**Before:**
```json
{
  "job_id": "job_abc123",
  "plan_id": "plan_xyz789",
  "tasks": [...],  // Full plan embedded
  "input": {...}
}
```

**After:**
```json
{
  "job_id": "job_abc123",
  "plan_id": "plan_xyz789",  // Reference only
  "input": {...},
  "input_index": 0,
  "status": "pending",
  "created_at": 1234567890
}
```

**Migration Path for AGW:**
1. Deploy AGQ with this change
2. Update AGW to new workflow:
   - Pop `job_id` from queue (BRPOPLPUSH)
   - Call `JOB.GET <job_id>` to get job metadata
   - Call `PLAN.GET <plan_id>` to retrieve plan
   - Execute tasks with input data
   - Update job status
3. Restart workers to use new format

**Why This Matters:**
- Enables plan reuse (plans stored once, referenced many times)
- Storage efficiency (no duplicate plan data)
- Proper Layer 2 (Plan) and Layer 3 (Job) separation
- Foundation for Actions layer (many jobs, same plan, different inputs)

### Added

#### New Commands
- `JOB.GET <job_id>` - Retrieve job metadata with plan_id reference (#46)
  - Returns JSON with: `job_id`, `plan_id`, `input`, `status`, `created_at`, `input_index`
  - Required for workers to fetch job details after queue pop
  - Authentication required
  - Input validation to prevent injection attacks

### Security

#### Input Size Validation (#46)
- Added validation for serialized input size (10MB limit) after JSON serialization
- Prevents resource exhaustion attacks
- Applies to each input in ACTION.SUBMIT
- Validation occurs AFTER serialization to catch actual storage size

#### Rate Limiting (#46)
- Added rate limiting for JOB.GET command (100 requests/second, 6000/minute)
- Prevents DoS attacks from malicious or misconfigured workers polling repeatedly
- Lightweight limit appropriate for hash lookup operations

## [0.1.0] - 2025-11-19

### Initial Release
- RESP protocol server with authentication
- Plan storage and submission (PLAN.SUBMIT, PLAN.LIST, PLAN.GET)
- Action submission with job creation (ACTION.SUBMIT, ACTION.LIST, ACTION.GET)
- Operational visibility commands (JOBS.LIST, WORKERS.LIST, QUEUE.STATS)
- redb-based persistent storage
- Job queuing (queue:ready)
- Worker heartbeat tracking
- Rate limiting for ACTION.SUBMIT (100/minute)
