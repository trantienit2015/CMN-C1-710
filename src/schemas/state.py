"""AgentCore Platform v1.0 - CMN-C1-710 GCPIAMPolicyAttachAgent state."""

# ADR-005: State must be a flat TypedDict - never Pydantic BaseModel.
# LangGraph checkpoints use msgpack serialization; Pydantic objects
# cause silent corruption.  Extend AgentState with agent-specific
# fields only.  Do NOT add credentials, secrets, or Pydantic models.

import json
from typing import Any, NotRequired, Optional

from framework.schemas.agent_state import AgentState


def to_json(value: Any) -> Optional[str]:
    """Serialize a list/dict State value to a compact JSON string (ADR-005, msgpack-safe).

    Returns None for None so the field stays a true Optional[str].
    """
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def from_json(value: Any, default: Any) -> Any:
    """Deserialize a JSON-string State value back to its list/dict form.

    Tolerant by design: None/empty -> default; an already-native list/dict (e.g. a value
    supplied directly in a unit test) passes through unchanged; a malformed string -> default.
    """
    if value is None or value == "":
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class State(AgentState):
    """Agent state for the GCP IAM policy-attach agent.

    Add only fields specific to this agent below. All shared fields
    (user_input, status, session_id, node_history, error_log, hitl_*, etc.)
    are inherited from AgentState.

    All agent-specific fields are NotRequired (written mid-pipeline; absent
    from early checkpoints - C8). Nested dict/list step outputs are stored as
    JSON strings via to_json()/from_json() (ADR-005).

    Security note: GCP credentials (ADC / Workload Identity / SA key) are
    NEVER stored in state - secrets are accessed via ctx.secrets.require()
    at the entry point. Only non-secret binding metadata is persisted.
    """

    # -- Step 1 InputParse output - resolved binding intent ------------------
    principal: NotRequired[str]  # fully qualified principal (serviceAccount:... / user:...)
    role_id: NotRequired[str]  # concrete GCP role id (roles/...)
    resource_path: NotRequired[str]  # target resource path (project / bucket / dataset)
    sensitivity_tier: NotRequired[str]  # "viewer" | "editor" | "owner"
    # Ambiguity candidates when principal/role could not be uniquely resolved (JSON list).
    resolution_candidates: NotRequired[str | None]
    confidence_flags: NotRequired[str | None]  # JSON list of low-confidence markers

    # -- Step 2 WhitelistCheck output ----------------------------------------
    allowlist_verdict: NotRequired[str]  # "pass" | "fail"
    allowlist_reason: NotRequired[str]

    # -- Step 3 ApprovalGate output ------------------------------------------
    approval_status: NotRequired[str]  # "approved" | "rejected" | "auto" | "paused"

    # -- Step 4 GCPAPICall output --------------------------------------------
    applied_etag: NotRequired[str]  # etag returned by setIamPolicy
    binding_result: NotRequired[str | None]  # JSON {principal, role, resource, etag}

    # -- Final validated output contract (JSON strings, ADR-005) -------------
    audit_metadata: NotRequired[str | None]
