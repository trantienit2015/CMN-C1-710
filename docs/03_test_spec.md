# CMN-C1-710 — Test Specification

## Test Strategy

Deterministic-core: the LLM and the GCP backend are injected fakes, so the full suite runs
offline. Unit tests cover each node (success + error/edge). Integration tests compile the graph
and invoke it end-to-end. Proof-of-boundary tests verify framework invariants.

## Unit Tests (`tests/unit/`)

### `test_pre_process_node.py` — InputParseNode
| ID | Test | Expected |
|---|---|---|
| U-P1 | trust level | `required_trust_level == INTERNAL` |
| U-P2 | success (structured triple) | SUCCESS; principal qualified; tier resolved |
| U-P3 | embedded SA key | ERROR (S-2 auto-reject) |
| U-P4 | embedded 個人番号 | ERROR |
| U-P5 | ambiguous principal | ERROR + `resolution_candidates` (no guess) |
| U-P6 | invalid role shape | ERROR (never invented) |
| U-P7 | `_extra_security_gate_input` blocks leaked credential | ERROR dict (no raise) |
| U-P8 | `_extra_security_gate_input` clean passthrough | returns state unchanged |

### `test_main_node.py` — PolicyAttachNode
| ID | Test | Expected |
|---|---|---|
| U-M1 | trust level | INTERNAL |
| U-M2 | viewer success | SUCCESS; etag applied |
| U-M3 | role not allowlisted | ERROR hard block |
| U-M4 | resource not allowlisted | ERROR hard block |
| U-M5 | empty allowlist | ERROR fail-closed |
| U-M6 | owner + HITL disabled | ERROR "HITL required" (no silent approve) |
| U-M7 | etag 409 → retry | SUCCESS after one re-read |
| U-M8 | etag conflict exhausted | ERROR (no overwrite) |
| U-M9 | upstream error short-circuit | ERROR |
| U-M10 | execute signature / no `_invoke_impl` | contract holds |

### `test_hitl_approval.py` — HITL D6
| ID | Test | Expected |
|---|---|---|
| U-H1 | owner tier first pass | raises `GraphInterrupt` |
| U-H2 | resume with approval | SUCCESS; binding applied |
| U-H3 | editor tier | raises `GraphInterrupt` |

### `test_post_process_node.py` — OutputValidateNode
| ID | Test | Expected |
|---|---|---|
| U-O1 | trust level declared | ANONYMOUS |
| U-O2 | output contract | SUCCESS; ISMS A.9.2.2 metadata |
| U-O3 | upstream error short-circuit | ERROR |
| U-O4 | `_extra_security_gate_output` redacts SA key | `[REDACTED_SA_KEY]`, rest preserved |
| U-O5 | clean passthrough | state unchanged |

## Integration Tests (`tests/integration/test_graph.py`)
| ID | Test | Expected |
|---|---|---|
| I-1 | full pipeline (viewer) | SUCCESS; ≥5 nodes; binding + ISMS metadata in output |
| I-2 | whitelist block (owner) | error/cancelled |
| I-3 | ANONYMOUS caller | error/cancelled (S-1 denied) |

## Proof-of-Boundary Tests (`tests/proof_of_boundary/`)
| PB | File | Verifies |
|---|---|---|
| PB-2 | `test_state_safety.py` | state holds only JSON-serializable primitives |
| PB-4 | `test_import_isolation.py` | no `agenticstar` / `mediator` / other-agent imports |
| PB-6 | `test_pb_invoke_order.py` | S-1 → node_start → S-2 → execute → S-3 → node_complete per node |
| PB-7 | `test_pb7_hitl_interrupt_propagation.py` | `interrupt()` raises `GraphInterrupt`, not swallowed to error |

## Framework Compliance (TC map)

TC-01 state contract (PB-2) · TC-02 SecurityViolation-equivalent (U-P3/P4) · TC-03 no credentials
in src (CI `gate-credential-scan`) · TC-05 `emit_trace_event` in every `execute()` · TC-06/07 gate
hooks (U-P7, U-O4) · TC-08 trust level enforced (I-3).

## 1. Deployment path tests

### TC-DEP-01 Marketplace entry point identity — `tests/unit/test_cli_entry_point.py`

| Case | Expected |
|---|---|
| Identity is concrete | `agent_name` / `namespace` are non-empty and not the runner default |
| Identity matches the HTTP entry point | the values equal what `src/api/server.py` passes to `secrets_factory`; where that entry point provisions no secrets, they equal the manifest `namespace` and the lower-cased template id |
| The runner call uses the constants | `run_agent_marketplace` is called with the module constants, not inline literals |

### TC-DEP-02 Standalone entry point boundary — `tests/proof_of_boundary/test_server_llm_injection.py`

| Case | Expected |
|---|---|
| Boots with no credential provisioned | the module imports and the app/agent objects are constructed |
| External bearer never reaches the internal level | resolves to the verified-external level |
| Staging runner credential reaches the internal level | resolves to the internal level |
| Wrong or missing bearer while auth is enabled | rejected with 401 |
