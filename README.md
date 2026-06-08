# Sentinel

**Autonomous SRE for air-gapped infrastructure.** Sentinel detects infrastructure anomalies, has a *local* LLM diagnose them, validates every proposed fix through a deterministic policy engine, asks a human to approve, and then executes — all without a single byte leaving the customer's network.

![Sentinel architecture](docs/architecture.png)

> **Status — honest version.** Sentinel is a working end-to-end prototype, built as a personal learning project to go deep on distributed systems, gRPC, local LLM integration, and safe automation. It is *not* a production product. The full chain runs and is demonstrable; the "Roadmap" section below is explicit about what is finished and what is not.

---

## The problem

Modern observability is passive. Tools like Prometheus and Grafana tell you *that* something is wrong, but a human still has to diagnose the cause and type the fix — often at 3 a.m.

LLM assistants could close that gap, but they send logs, configs, and environment data to public cloud APIs. For regulated sectors — defense, finance, healthcare, utilities — that is a non-starter, legally before technically.

Sentinel closes the gap **without breaking the constraint**: detection, LLM inference, validation, and execution all happen inside the customer's own network. Zero data egress.

## The core idea: separate the probabilistic from the deterministic

An LLM is probabilistic — given the same input it can answer differently, and occasionally dangerously. Letting it run commands as root unsupervised would be reckless. Sentinel draws a hard line:

- **The LLM proposes.** It diagnoses the anomaly and drafts a remediation plan.
- **A deterministic engine disposes.** Every command is parsed and judged by a fixed, verifiable, repeatable rule set *before* it can run.

That engine — the **policy engine** — is the moat between an LLM's output and a privileged shell. It is the most distinctive part of the system.

## How it works

```mermaid
flowchart LR
    A[Anomaly<br/>detected] --> B[Capture<br/>+ context]
    B --> C[Transport<br/>gRPC]
    C --> D[Reason<br/>local LLM]
    D --> E[Validate<br/>policy engine]
    E --> F[Persist<br/>PostgreSQL]
    F --> G[Approve<br/>operator]
    G --> H[Execute<br/>node, dry-run]
```

1. **Detect** — the node spots a metric over threshold (e.g. memory at 85%).
2. **Capture** — it builds a telemetry event, enriched with context (e.g. the top memory-consuming processes).
3. **Transport** — the event travels to the hub over gRPC.
4. **Reason** — the hub prompts a locally-hosted LLM, which returns a structured JSON plan: root cause, risk level, confidence, ordered commands.
5. **Validate** — the policy engine judges each command: `allow`, `review`, or `block`.
6. **Persist** — the full incident is saved to PostgreSQL in a single transaction.
7. **Approve** — an operator reviews the incident on the dashboard and approves or rejects.
8. **Execute** — the node pulls the approved plan, runs only the `allow` commands (dry-run by default), and reports the outcome.

## Architecture

Four layers, plus persistence and an operator dashboard.

| Layer | Role |
|-------|------|
| **Edge node** (Go) | Per-server daemon: profiles the host, detects anomalies, executes approved plans. |
| **Transport** (gRPC + Protobuf) | Typed, contract-first communication between node and hub. |
| **Reasoning hub** (Go) | Receives telemetry, queries the local LLM, runs the pipeline, serves the API. |
| **Policy engine** (Go) | Deterministically validates every command the LLM proposes. |

### The policy engine, in a little more detail

Rather than naive string matching (easily bypassed), the engine **parses each command into an abstract syntax tree** using a real shell grammar parser. That lets it catch dangerous commands even when hidden inside `eval`, `sh -c`, `&&` chains, command substitutions, or redirection targets (`>`, `>>`). Rules are evaluated most-dangerous-first; a plan's verdict equals its worst command. A safety guarantee worth stating plainly: **the node executes only `allow` commands — `review` and `block` are never executed automatically, even after operator approval.** Defense in depth: the deterministic gate filters commands, the human approves the set.

### A finding worth sharing

Early on, given the same anomaly ("memory at 82%"), the LLM produced vague, shifting guesses. After enriching the event with the actual top memory-consuming processes — carried in a free-form labels map, **with no schema change** — the diagnosis became precise and repeatable, naming the specific culprit process. The lesson generalizes: *the quality of an LLM's diagnosis depends on the quality of the context you give it, not just on the model's size.*

## Tech stack

- **Go** — node, hub, policy engine
- **gRPC + Protocol Buffers** — typed transport, code generated from `.proto`
- **Ollama** (dev) / **vLLM** (planned, production) — local LLM inference; model: `qwen2.5-coder:7b`
- **PostgreSQL** — persistence, with versioned migrations (`golang-migrate`) and type-safe queries (`sqlc`)
- **mvdan/sh** — shell AST parsing in the policy engine
- **HTML / CSS / JS** — the operator dashboard (no framework, served by the hub)

## Roadmap — what's done and what isn't

**Done and demonstrable end-to-end:** detection, capture, gRPC transport, LLM reasoning, deterministic policy validation, transactional persistence, operator dashboard with filtering and an approve/reject workflow, and node-side execution (dry-run) that reports back and closes the incident lifecycle. The policy engine and executor have automated tests covering their safety guarantees.

**Planned / in progress (tracked, not hidden):**
- mTLS on the transport (currently plaintext)
- Asynchronous pipeline (the node currently waits for the LLM synchronously)
- vLLM on GPUs for production inference
- Hash-chained audit log (the message exists in the data contract; not yet wired)
- Resilient hub startup (degrade gracefully when the LLM is unreachable)
- Packaging (RPM), k3s deployment, secret management via a vault
- More anomaly types beyond memory and disk

## Running it locally

> Requires Go, Docker, `protoc`, `golang-migrate`, `sqlc`, and Ollama.

```bash
# 1. Start PostgreSQL
docker run -d --name sentinel-db \
  -e POSTGRES_USER=sentinel -e POSTGRES_PASSWORD=sentinel_dev \
  -e POSTGRES_DB=sentinel -p 5432:5432 postgres:16

# 2. Apply the schema
migrate -path hub/migrations \
  -database "postgres://sentinel:sentinel_dev@localhost:5432/sentinel?sslmode=disable" up

# 3. Start the local LLM
ollama serve   # with qwen2.5-coder:7b pulled

# 4. Run the hub (gRPC :50051, dashboard :8080)
go run ./hub

# 5. Run a node
go run ./node
```

Open the dashboard at `http://localhost:8080`.

## Design principles

- **Clear component boundaries** — implementations can be swapped (Ollama → vLLM, dry-run → live) without rewrites.
- **Schema as the source of truth** — both messages (Protobuf) and data access (sqlc) are generated from a formal definition.
- **Safe by default** — the default state is always the prudent one (dry-run; unknown verdict treated as needs-review; the policy filter as the final technical gate).
- **Probabilistic proposes, deterministic disposes** — the central safety idea, and the conceptual contribution of the project.

---

*Built as a personal project to learn distributed systems, gRPC, local LLM integration, and safe automation, starting from scratch on a Mac.*
