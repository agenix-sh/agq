# AGX Project Roadmap  
**Version:** 0.1  
**Status:** Draft

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
A user provides intent → AGX generates a plan → AGQ queues it → AGW executes steps deterministically.

### Required Repositories
1. `agenix-sh/agx`  
2. `agenix-sh/agq`  
3. `agenix-sh/agw`  
4. (Phase 2) `agenix-sh/agx-ocr`

---

## 2.1 AGX (Planner)

Deliverables:
- CLI skeleton  
- Plan Mode:
  - `PLAN new`  
  - `PLAN add "<instruction>"`  
  - `PLAN preview`  
  - `PLAN submit`  
- LLM integration for plan shaping  
- JSON plan schema  
- Ops-mode scaffolding:
  - `JOBS list`  
  - `WORKERS list`  
  - `QUEUE stats`  

---

## 2.2 AGQ (Queue/Scheduler)

Deliverables:
- Embedded HeroDB (`redb`)  
- Minimal RESP server  
- Session-key authentication  
- List + zset queue model  
- Job storage + metadata  
- Scheduling loop  
- Failure handling & retry logic  
- Worker heartbeat tracking  

---

## 2.3 AGW (Worker)

Deliverables:
- RESP client with auth  
- Blocking queue fetch  
- Step execution:
  - Unix tools  
  - stub agent tools  
- Output capture + results posting  
- Heartbeat loop  

---

## 2.4 End-to-End Demo

Example workflow:
- User: “sort and deduplicate this file”  
- AGX generates plan (sort → uniq → wc)  
- AGQ queues steps  
- AGW executes and returns result  

Completion Criteria:
- macOS + Linux compatible  
- Single-script installation  
- Working plan → execution flow  

---

# 3. Phase 2 — First Real Agent Tool (`agx-ocr`)

Deliverables:
- `agx-ocr` binary  
- Local OCR engine (Tesseract or alternative)  
- Plans may reference it as `{"tool": "agx-ocr"}`  
- AGW tool registration  
- Demo workflow: receipt image → text extraction  

---

# 4. Phase 3 — Ecosystem Growth

Deliverables:
- More agent tools (`agx-summarise`, `agx-transcode`, etc.)  
- Worker capability negotiation  
- Advanced plan features (branching, conditionals)  
- Web UI for jobs  
- Enhanced REPL (sessions, editing)  

---

# 5. Phase 4 — AOA Alignment

Deliverables:
- AU registry  
- AU lifecycle management  
- AU evaluation + fitness scoring  
- Multi-node AGQ  
- Distributed scheduling  
- Agent memory layer  
- Integration with graph planners (GAP)  
- Semantic routing  

---

# End of Roadmap Document
