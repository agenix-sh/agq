# AGX Architecture  
**AGX Ecosystem: Planner, Queue Manager, Worker Mesh, and Agentic Tools**  
**Version:** 0.1  
**Status:** Draft (Decision-aligned)

---

## 1. Introduction

The **AGX ecosystem** is a minimal, Unix-philosophy-aligned system enabling **agentic plans** to be generated via LLMs and executed deterministically on local hardware. It emphasizes:

- **Zero external dependencies**  
- **Pure Rust** binaries  
- **Embedded data store** for durability  
- **A clear separation between planning and execution**  
- **Extensibility through single-purpose agentic tools (agenix philosophy)**

AGX is the foundation layer for further AOA ambitions, providing a minimal, powerful, local-first execution substrate.

---

## 2. System Overview

The ecosystem consists of four conceptual components:

1. **AGX** – Planner + Orchestrator (creates JSON plans)  
2. **AGQ** – Queue + Scheduler + Dispatcher  
3. **AGW** – Workers that execute plan steps  
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
`agx` → plan  
`agq` → queue/schedule  
`agw` → execute  
`agx-*` → specialised tool AUs

### 3.3 Redis-CLI-style Protocol
All components communicate using RESP over TCP with session-key authentication.

### 3.4 HeroDB Embedded Store (redb)
Single-file ACID KV store backing Redis-compatible primitives:
- lists  
- sorted sets  
- hashes  

### 3.5 Deterministic Execution
Workers cannot call LLMs.  
Execution is predefined, controlled, and sequential.

### 3.6 JSON Plan Format
A deterministic, inspectable execution description.

---

## 4. Detailed Component Architecture

### 4.1 `agx`: Planner
- LLM-assisted REPL  
- Generates JSON plans  
- `PLAN new`, `PLAN refine`, `PLAN submit`  
- Can operate in Ops Mode (query jobs/workers)

### 4.2 `agq`: Queue/Scheduler
- Embedded HeroDB  
- Plan acceptance  
- Job storage  
- Worker dispatch  
- Failure handling and retries

### 4.3 `agw`: Worker
- RESP client  
- Heartbeats  
- Executes Unix + agentic tools  
- Stateless linear executor

### 4.4 Agent Tools
- Separate binaries  
- stdin → stdout  
- Focused, single-purpose modules

---

## 5. Security Model
- Session key required for all commands  
- Later enhancements: Unix sockets, mTLS, scoped keys

---

## 6. Keyspace Layout (HeroDB)
Plans stored as `plan:<id>`  
Jobs: `job:<id>:plan`, `job:<id>:status`, etc.  
Queues: `queue:ready`, `queue:scheduled`  
Workers: `worker:<id>:alive`, `worker:<id>:tools`

---

## 7. Lifecycle
User → AGX Plan → Submit → AGQ Schedules → AGW Executes → Results stored

---

## 8. Future Extensions
Clustered AGQ  
Graph-based execution  
AU lifecycle manager  
Semantic registry  
Agent evaluation  
