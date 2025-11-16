# AGX Project Roadmap
**Version:** 0.2
**Status:** Draft (Nomenclature-aligned)

**Nomenclature**: This document uses the canonical terminology defined in `agx/docs/EXECUTION-LAYERS.md`. See also: `docs/NOMENCLATURE.md`.

---

# 1. Overview

This roadmap defines the AGX delivery sequence:

- **Phase 1** → Plan generation + execution environment  
- **Phase 2** → First real agent tool: `agx-ocr`  
- **Phase 3** → Ecosystem growth  
- **Phase 4** → Full AOA alignment  

---

# 2. Phase 1 — Core System (MVP Execution Pipeline)

Goal:
A user provides intent → AGX generates a Plan → AGQ creates Jobs → AGW executes Tasks deterministically.

### Required Repositories
1. `agenix-sh/agx`  
2. `agenix-sh/agq`  
3. `agenix-sh/agw`  
4. (Phase 2) `agenix-sh/agx-ocr`

---

## 2.1 AGX (Planner)

Deliverables:
- CLI skeleton
- Plan Mode (generates Plans):
  - `PLAN new`
  - `PLAN add "<instruction>"`
  - `PLAN preview`
  - `PLAN.SUBMIT` to AGQ
- LLM integration for Plan generation
- JSON Plan schema (list of Tasks)
- `ACTION.SUBMIT` to create Jobs
- Ops-mode scaffolding:
  - `JOB.LIST`
  - `JOB.STATUS`
  - `WORKERS list`
  - `QUEUE stats`  

---

## 2.2 AGQ (Queue/Scheduler)

Deliverables:
- Embedded HeroDB (`redb`)
- Minimal RESP server
- Session-key authentication
- `PLAN.SUBMIT` endpoint (store Plans)
- `ACTION.SUBMIT` endpoint (create Jobs from Plans)
- `JOB.STATUS` and `JOB.LIST` endpoints
- Job queue model (list + zset)
- Job storage + metadata
- Scheduling loop
- Failure handling & retry logic
- Worker heartbeat tracking  

---

## 2.3 AGW (Worker)

Deliverables:
- RESP client with auth
- Blocking queue fetch (pulls Jobs via `BRPOP`)
- Task execution within Jobs:
  - Unix tools
  - Stub agent tools
- Sequential execution of Tasks in a Plan
- Output capture + results posting
- Heartbeat loop  

---

## 2.4 End-to-End Demo

Example workflow:
- User: "sort and deduplicate this file"
- AGX generates Plan with 3 Tasks (sort → uniq → wc)
- AGX submits Plan via `PLAN.SUBMIT`
- AGX creates Action via `ACTION.SUBMIT` → AGQ creates Job
- AGQ enqueues Job
- AGW pulls Job and executes Tasks sequentially
- AGW returns results

Completion Criteria:
- macOS + Linux compatible
- Single-script installation
- Working Plan → Job → Task execution flow  

---

# 3. Phase 2 — First Real Agent Tool (`agx-ocr`)

Deliverables:
- `agx-ocr` binary
- Local OCR engine (Tesseract or alternative)
- Plans reference it as a Task: `{"task": "agx-ocr", "command": "agx-ocr"...}`
- AGW tool registration
- Demo workflow: receipt image → text extraction  

---

# 4. Phase 3 — Ecosystem Growth

Deliverables:
- More agent tools (`agx-summarise`, `agx-transcode`, etc.)
- Worker capability negotiation
- Advanced Plan features (branching, conditionals, Task dependencies)
- Web UI for Job monitoring
- Enhanced REPL (sessions, editing)
- Action monitoring and analytics  

---

# 5. Phase 4 — AOA Alignment

Deliverables:
- AU registry
- AU lifecycle management
- AU evaluation + fitness scoring
- Multi-node AGQ
- Distributed Job scheduling
- Workflow orchestration (multi-Action coordination)
- Agent memory layer
- Integration with graph planners (GAP)
- Semantic routing  

---

# End of Roadmap Document
