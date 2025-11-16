# AGX Architecture
**AGX Ecosystem: Planner, Queue Manager, Worker Mesh, and Agentic Tools**
**Version:** 0.2
**Status:** Draft (Decision-aligned, Nomenclature-aligned)

**Nomenclature**: This document uses the canonical terminology defined in `agx/docs/EXECUTION-LAYERS.md`. See also: `docs/NOMENCLATURE.md`.

---

## 1. Introduction

The **AGX ecosystem** is a minimal, Unix-philosophy-aligned system enabling **agentic Plans** to be generated via LLMs and executed deterministically on local hardware. It emphasizes:

- **Zero external dependencies**  
- **Pure Rust** binaries  
- **Embedded data store** for durability  
- **A clear separation between planning and execution**  
- **Extensibility through single-purpose agentic tools (agenix philosophy)**

AGX is the foundation layer for further AOA ambitions, providing a minimal, powerful, local-first execution substrate.

---

## 2. System Overview

The ecosystem consists of four conceptual components:

1. **AGX** – Planner + Orchestrator (creates JSON Plans)
2. **AGQ** – Queue + Scheduler + Dispatcher (manages Jobs)
3. **AGW** – Workers that execute Tasks within Jobs
4. **AGX-* tools** – Single-responsibility agent tools (`agx-ocr`, etc.)

Phase 1 binaries:

- `agx`
- `agq`
- `agw`

Agent tools follow in Phase 2+.

---

## 3. Core Design Decisions

### 3.1 Rust-only Embedded Deployment
Ensures cross-platform (macOS/Linux) installations with zero external dependencies.

### 3.2 Separation of Responsibilities
`agx` → Generate Plans and Actions
`agq` → Store Plans, manage Jobs, schedule Actions
`agw` → Execute Tasks within Jobs
`agx-*` → Specialised tool AUs (implement Tasks)

### 3.3 Redis-CLI-style Protocol
All components communicate using RESP over TCP with session-key authentication.

### 3.4 Embedded Storage (redb)
Single-file ACID KV store backing Redis-compatible primitives:
- strings (GET/SET/DEL/EXISTS)
- lists (LPUSH/RPOP/BRPOP)
- sorted sets (ZADD/ZRANGE)
- hashes (HSET/HGET/HDEL)  

### 3.5 Deterministic Execution
Workers cannot call LLMs.  
Execution is predefined, controlled, and sequential.

### 3.6 JSON Plan Format
A Plan is a deterministic, inspectable list of Tasks.

---

## 4. Detailed Component Architecture

### 4.1 `agx`: Planner
- LLM-assisted REPL
- Generates JSON Plans
- Submits Plans and Actions to AGQ
- Can operate in Ops Mode (query Jobs/workers)

### 4.2 `agq`: Queue/Scheduler
- Embedded redb storage (ACID key-value database)
- Stores Plans (via `PLAN.SUBMIT`)
- Creates and manages Jobs (via `ACTION.SUBMIT`)
- Dispatches Jobs to workers
- Tracks Job lifecycle, retries, and failures

### 4.3 `agw`: Worker
- RESP client
- Heartbeats
- Pulls Jobs from AGQ (via `BRPOP`)
- Executes Tasks within Jobs sequentially
- Runs Unix commands and agentic tools

### 4.4 Agent Tools
- Separate binaries
- Implement Tasks (atomic operations)
- stdin → stdout
- Focused, single-purpose modules

---

## 5. Security Model
- Session key required for all commands  
- Later enhancements: Unix sockets, mTLS, scoped keys

---

## 6. Keyspace Layout (redb Storage)

Per the canonical 5-layer model:

**Plans** (stored definitions):
- `plan:<id>` → Plan JSON (list of Tasks)

**Jobs** (runtime instances):
- `job:<id>:plan` → Plan ID reference
- `job:<id>:status` → pending/running/completed/failed/dead
- `job:<id>:input` → Input data for this Job
- `job:<id>:output` → Results

**Queues**:
- `queue:ready` → Jobs ready for execution
- `queue:scheduled` → Jobs scheduled for future

**Workers**:
- `worker:<id>:alive` → Heartbeat timestamp
- `worker:<id>:tools` → Registered tool capabilities

**Implementation:** All keys use string encoding with Redis RESP protocol. The embedded redb database provides ACID guarantees and single-file storage at `~/.agq/data.redb` by default.

---

## 7. Lifecycle

**Single Job execution**:
1. User defines objective
2. AGX generates Plan (list of Tasks)
3. AGX submits Plan via `PLAN.SUBMIT` → AGQ stores
4. AGX creates Action via `ACTION.SUBMIT` → AGQ creates Job(s)
5. AGQ enqueues Job to `queue:ready`
6. AGW pulls Job via `BRPOP`
7. AGW executes each Task sequentially
8. AGW reports results → AGQ stores
9. AGQ updates Job status to completed/failed

**Action (parallel execution)**:
- Same Plan, multiple inputs
- AGQ creates one Job per input
- Multiple AGWs execute Jobs in parallel

---

## 8. Future Extensions
- Clustered AGQ
- DAG-based Plans (Task dependencies)
- Workflows (multi-Action orchestration)
- AU lifecycle manager
- Semantic registry
- Agent evaluation  
