"""AgentCore Platform v1.0 - CMN-C1-710 PolicyAttachNode (main slot).

Steps 3-5 of the design workflow, in one privileged node:
  - Step 3 WhitelistCheck - deterministic role + resource double allowlist hard
    block (no LLM override, no suppress).
  - Step 4 ApprovalGate - HITL D6 interrupt() for owner/editor-tier roles when
    hitl.enabled AND state["hitl_allowed"] is not False; deterministic tier
    pass-through (owner/editor -> auto-FAIL "HITL required", viewer -> pass)
    otherwise. hitl_draft guards against re-execution on resume.
  - Step 5 GCPAPICall - etag-guarded read-modify-write (getIamPolicy -> append ->
    setIamPolicy); 409 -> single re-read + retry -> ERROR. S-4 emit_trace_event
    inline for the mutation (ISMS A.9.2.2 / NISC evidence).

Framework owns the interrupt() pause/resume mechanism; this node owns the
trigger condition. The raw setIamPolicy call is factored into the service layer
(GcpIamPolicyClient) - this node owns only node/state/security plumbing.
"""

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from shared.services.events import emitter
from shared.services.events.types import EventType
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from langgraph.types import interrupt
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import to_json
from src.services.gcp_iam_client import GcpIamError, GcpIamPolicyClient, check_allowlists

_HITL_TIERS = {"owner", "editor"}  # tiers that require human confirmation


class PolicyAttachNode(FunctionNode):
    """WhitelistCheck (deterministic) + ApprovalGate (HITL D6) + GCP etag write."""

    # S-1: privilege-bearing IAM mutation -> INTERNAL only.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def __init__(
        self,
        gcp_client: GcpIamPolicyClient | None = None,
        allowed_roles: list[str] | None = None,
        resource_allowlist: list[str] | None = None,
        hitl_enabled: bool = False,
    ):
        # Immutable deps only - node stays stateless.
        self._gcp_client = gcp_client or GcpIamPolicyClient()
        self._allowed_roles = allowed_roles or []
        self._resource_allowlist = resource_allowlist or []
        self._hitl_enabled = hitl_enabled

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Short-circuit if an upstream node already errored.
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Working on the request...",
            metadata={"step": "main"},
        )
        if state.get("status") in (AgentStatus.ERROR.value, AgentStatus.ERROR.value):
            return {"status": AgentStatus.ERROR.value}

        principal = state.get("principal", "")
        role_id = state.get("role_id", "")
        resource_path = state.get("resource_path", "")
        tier = state.get("sensitivity_tier", "owner")

        # -- Step 3: deterministic double allowlist - hard block, no override --
        ok, reason = check_allowlists(role_id, resource_path, self._allowed_roles, self._resource_allowlist)
        if not ok:
            emit_trace_event(
                "whitelist_blocked",
                {"correlation_id": state.get("correlation_id"), "role_id": role_id, "reason": reason},
                state,
            )
            return {
                "allowlist_verdict": "fail",
                "allowlist_reason": reason,
                "status": AgentStatus.ERROR.value,
                "error_log": [f"PolicyAttachNode: S-allowlist hard block - {reason}"],
            }

        # -- Step 4: ApprovalGate (HITL D6 when enabled, tier policy otherwise) --
        approval_status = "auto"
        if tier in _HITL_TIERS:
            # hitl_allowed=False -> automated pipeline (invoked via GraphNode / gateway):
            # interrupt() would deadlock, so it MUST NOT be reached. This node never
            # silent-approves a privileged tier, so the unattended path fails closed,
            # exactly like the hitl.enabled=false branch below.
            hitl_allowed = state.get("hitl_allowed", True)
            if self._hitl_enabled and hitl_allowed:
                draft = state.get("hitl_draft")
                if draft is None:
                    draft = {"principal": principal, "role": role_id, "resource": resource_path, "tier": tier}
                    emit_trace_event(
                        "approval_interrupt",
                        {"correlation_id": state.get("correlation_id"), "role_id": role_id, "tier": tier},
                        state,
                    )
                    feedback = interrupt({"draft": draft, "reason": f"{tier}-tier role requires human approval"})
                    decision = _decision_of(feedback)
                    if decision != "approved":
                        return {
                            "hitl_draft": to_json(draft),
                            "hitl_feedback": feedback,
                            "approval_status": "rejected",
                            "status": AgentStatus.ERROR.value,
                            "error_log": ["PolicyAttachNode: human rejected the binding"],
                        }
                    approval_status = "approved"
                else:
                    approval_status = "approved"  # resumed after approval
            else:
                # HITL unavailable (disabled in config, or suppressed by the caller via
                # hitl_allowed=False) -> owner/editor tier auto-FAILs, never silent approve.
                blocked_by = "hitl.enabled is false" if not self._hitl_enabled else "hitl_allowed is false"
                emit_trace_event(
                    "approval_hitl_required",
                    {
                        "correlation_id": state.get("correlation_id"),
                        "role_id": role_id,
                        "tier": tier,
                        "blocked_by": blocked_by,
                    },
                    state,
                )
                return {
                    "approval_status": "rejected",
                    "status": AgentStatus.ERROR.value,
                    "error_log": [f"PolicyAttachNode: {tier}-tier role requires HITL, but {blocked_by}"],
                }

        # -- Step 5: etag-guarded read-modify-write on GCP ------------------
        try:
            binding = self._gcp_client.attach_binding(resource_path, principal, role_id)
        except GcpIamError as exc:
            emit_trace_event(
                "gcp_setiampolicy_error",
                {"correlation_id": state.get("correlation_id"), "error": str(exc)},
                state,
            )
            return {
                "allowlist_verdict": "pass",
                "approval_status": approval_status,
                "status": AgentStatus.ERROR.value,
                "error_log": [f"PolicyAttachNode: setIamPolicy failed - {exc}"],
            }

        # S-4: mutation audit - ISMS A.9.2.2 / NISC DevSecOps evidence.
        emit_trace_event(
            "iam_binding_applied",
            {
                "correlation_id": state.get("correlation_id"),
                "principal": principal,
                "role_id": role_id,
                "resource": resource_path,
                "approval_status": approval_status,
                "etag": binding.get("etag", ""),
            },
            state,
        )
        return {
            "allowlist_verdict": "pass",
            "approval_status": approval_status,
            "applied_etag": binding.get("etag", ""),
            "binding_result": to_json(binding),
            "result": to_json(binding),
            "status": AgentStatus.SUCCESS.value,
        }


def _decision_of(feedback: Any) -> str:
    """Normalise a HITL feedback payload into 'approved' / 'rejected'."""
    if isinstance(feedback, dict):
        d = str(feedback.get("decision", feedback.get("approved", ""))).lower()
        if d in ("approved", "approve", "true", "yes"):
            return "approved"
        return "rejected"
    if isinstance(feedback, bool):
        return "approved" if feedback else "rejected"
    return "approved" if str(feedback).lower() in ("approved", "approve", "yes", "true") else "rejected"
