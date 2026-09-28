"""AgentCore Platform v1.0 - CMN-C1-710 OutputValidateNode (post_process slot).

Step 6 of the design workflow: S-3 deterministic output gate. Scans the
result strings for SA-key / JWT patterns and redacts them (preservation variant -
the confirmed binding summary + audit reference are preserved, only the offending
substring is masked, and the redaction is logged). Assembles the locked output
contract returned to the caller.
"""

from datetime import datetime, timezone
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from shared.services.events import emitter
from shared.services.events.types import EventType
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json, to_json
from src.services.gcp_iam_client import build_output_contract, redact_sensitive_output


class OutputValidateNode(FunctionNode):
    """S-3 deterministic output gate: credential redaction + output-contract assembly."""

    # S-1: explicit by design, not inherited implicitly.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Preparing the result...",
            metadata={"step": "post_process"},
        )
        if state.get("status") in (AgentStatus.ERROR.value, AgentStatus.ERROR.value):
            return {"status": AgentStatus.ERROR.value}

        binding_result = from_json(state.get("binding_result"), {})
        approval_status = state.get("approval_status", "auto")
        scan_ts = datetime.now(timezone.utc).isoformat()

        contract = build_output_contract(binding_result, approval_status, scan_ts)
        payload = to_json(contract)

        emit_trace_event(
            "output_validated",
            {
                "correlation_id": state.get("correlation_id"),
                "role_id": contract["binding"].get("role", ""),
                "approval_status": approval_status,
            },
            state,
        )

        return {
            "binding_result": to_json(contract["binding"]),
            "audit_metadata": to_json(contract["audit_metadata"]),
            "result": payload,
            "formatted_output": payload,
            "status": AgentStatus.SUCCESS.value,
        }

    def _extra_security_gate_output(self, state: dict[str, Any]) -> dict[str, Any]:
        """S-3 domain hook: re-verify no SA key / token slipped through at the gate boundary."""
        text = state.get("result") or state.get("formatted_output") or ""
        if isinstance(text, str):
            redacted, was_redacted = redact_sensitive_output(text)
            if was_redacted:
                emit_trace_event("output_gate_redacted", {"field": "result"}, state)
                new_state = dict(state)
                new_state["result"] = redacted
                new_state["formatted_output"] = redacted
                return new_state
        return state
