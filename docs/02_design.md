# CMN-C1-710 — Design Specification

## Position in AgentCore Architecture

- **L1 Base**: `AgentBaseGraph` (L1 direct — fixed 3-slot pipeline, no autonomous loop)
- **Agent Class**: `Graph` (module `src.graph`) — inherits `AgentBaseGraph` (L1 direct)
- **Category**: Cat 1 — single technical capability (NL → GCP IAM policy binding attach)
- **Pattern**: ToolCallingAgent (the raw `setIamPolicy` call is a Tool in `src/services/gcp_iam_client.py`)
- **Industry**: CMN (industry-agnostic)
- **Trust level (agent default)**: `INTERNAL` (privilege-bearing IAM mutation)

## State Schema (`src/schemas/state.py`)

`class State(AgentState)` — flat TypedDict, all agent-specific fields `NotRequired`
(written mid-pipeline; ADR-005 msgpack-safe). Nested list/dict outputs stored as JSON
strings via `to_json()` / `from_json()`.

| Field | Type | Written by |
|---|---|---|
| `principal` | `str` | InputParse (fully qualified `serviceAccount:`/`user:`) |
| `role_id` | `str` | InputParse (concrete `roles/…`) |
| `resource_path` | `str` | InputParse (project/bucket/dataset path) |
| `sensitivity_tier` | `str` | InputParse (`viewer`/`editor`/`owner`) |
| `resolution_candidates` | `str\|None` (JSON) | InputParse (ambiguity fallback) |
| `allowlist_verdict` / `allowlist_reason` | `str` | PolicyAttach |
| `approval_status` | `str` | PolicyAttach (`auto`/`approved`/`rejected`) |
| `applied_etag` / `binding_result` | `str` / JSON | PolicyAttach |
| `audit_metadata` | JSON | OutputValidate |
| `hitl_draft` / `hitl_feedback` | (framework) | PolicyAttach (idempotency guard) / framework |

> **Security**: GCP credentials (ADC / Workload Identity / SA key) are NEVER in state —
> accessed via `ctx.secrets.require("gcp_sa_key")` at the entry point.

## Node Composition (flat 3-slot AgentBaseGraph pipeline)

```
START → initialize → pre_process → main → {route} → post_process → finalize → END
                                  \_ (RETRY, max 3) _/ pre_process
```

| Slot | Node | Steps | Responsibility |
|---|---|---|---|
| `pre_process` | `InputParseNode` | 1-2 | S-1 trust gate (INTERNAL) + S-2 credential/個人番号 scan (`_extra_security_gate_input`) + LLM three-way resolution (principal / role id / resource path), validated by deterministic service helpers |
| `main` | `PolicyAttachNode` | 3-5 | WhitelistCheck (deterministic role + resource double allowlist hard block) → ApprovalGate (HITL D6 `interrupt()` for owner/editor tier; tier pass-through when disabled) → `setIamPolicy` etag-guarded read-modify-write → S-4 `emit_trace_event` mutation evidence |
| `post_process` | `OutputValidateNode` | 6 | S-3 credential redaction (`_extra_security_gate_output`, preservation variant) + locked output-contract assembly |

## Security (5-layer)

- **S-1**: `required_trust_level = INTERNAL` on InputParse + PolicyAttach (privileged nodes); OutputValidate = ANONYMOUS. Agent default `INTERNAL` in `agent.yaml`.
- **S-2**: deterministic regex scan (SA private key, Bearer/JWT, credential fields, 個人番号) → `status=ERROR` (raise-free) in `execute()` + re-check in `_extra_security_gate_input()`.
- **S-3**: output gate redacts SA-key / JWT patterns while preserving the binding summary + audit reference (`_extra_security_gate_output()`). Secrets via `ctx.secrets.require("gcp_sa_key")` + entry-point `bound_secrets`/`secrets_factory`/`provision_secrets`; never `os.environ`, never in state.
- **S-4**: `emit_trace_event()` in every node's `execute()`; the mutation event (`iam_binding_applied`) carries requester/principal/role/resource/approval/etag — ISMS A.9.2.2 / NISC evidence.
- **S-5**: no credentials in source (CI `gate-credential-scan`).

## HITL (D6)

`hitl.enabled: true` + `memory_enabled: true` + `max_hitl: 8` in `agent.yaml`. Owner/editor-tier
bindings pause via `interrupt({draft, reason})` inside `PolicyAttachNode.execute()`; `hitl_draft`
guards re-execution on resume. When `hitl.enabled: false`, owner/editor tier auto-FAILs with
"HITL required" (never silent approve); viewer tier passes. PB-7 verifies interrupt propagation.

## Concurrency (etag read-modify-write)

`getIamPolicy` → append binding (idempotent) → `setIamPolicy` with the fetched etag. A 409
concurrent-edit conflict triggers a single re-read + retry, then `GcpIamError` → `status=ERROR`
(no blind overwrite).

## Dependencies

Deterministic-core: no `google-cloud-*` dependency pinned. A real deployment injects a
google-cloud-resource-manager-backed `backend` into `GcpIamPolicyClient` via graph config; tests
inject a fake backend. `dependencies = []` (framework from wheel).

## 1. Deployment entry points

The agent is reachable through two entry points, and both resolve their runtime inputs the same way.

| Entry point | File | Used by |
|---|---|---|
| Standalone HTTP | `src/api/server.py` | staging rehearsal, direct invocation |
| Marketplace one-shot Pod | `cli.py` | the platform runner (container `CMD`) |

Both read runtime parameters from `config/config.yaml` — the manifest carries discovery metadata
only — and both scope secrets to the same location (`namespace=cmn`, `agent_name=GCPIAMPolicyAttachAgent`), so a
secret provisioned for one path resolves identically on the other.

**No LLM client is constructed at either entry point.** The pipeline is deterministic; a client
may still be injected through `config["llm"]` by a caller that has one.

**Progress events.** Each pipeline stage emits a non-terminal progress event at its start, so a
caller sees the run advancing. Outside the Marketplace runtime the emitter resolves to a no-op, so
the same code is safe on every path. Terminal events belong to the platform runner and are never
emitted by this agent.

**Caller authentication at the standalone entry point.** A caller that no upstream middleware
vouched for stays anonymous unless it presents a deployment-level credential: the external bearer
token grants the verified-external level, and a separate staging-only runner credential is the only
way to reach the internal level. Trust established upstream is never changed.
