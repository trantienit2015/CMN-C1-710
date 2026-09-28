"""AgentCore Platform v1.0 - CMN-C1-710 InputParseNode (pre_process slot).

Steps 1-2 of the design workflow:
  - S-1 trust gate (INTERNAL - this agent mutates IAM policy, a privileged write)
  - S-2 deterministic credential/PII scan on the caller-supplied request (regex,
    NOT an LLM judgment; SecurityViolationError-equivalent behaviour is expressed
    as status=ERROR + error_log, raise-free per the S-2 hook contract)
  - LLM-essential three-way resolution: principal + role id + resource path.
    An injected llm proposes the triple; deterministic service helpers normalise
    and validate it (unknown role -> never invented; ambiguous principal ->
    candidates returned, no guess).
"""

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from shared.services.events import emitter
from shared.services.events.types import EventType
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import to_json
from src.services.gcp_iam_client import (
    normalize_principal,
    scan_for_embedded_credentials,
    sensitivity_tier,
    validate_role_id,
)


class InputParseNode(FunctionNode):
    """S-1 trust gate + S-2 credential scan + LLM three-way binding resolution."""

    # S-1: this node gates a privilege-bearing IAM write - only
    # INTERNAL callers (SRE via the governed frontend / enforcement workflow)
    # may submit a binding request. Not ANONYMOUS/VERIFIED_EXTERNAL.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def __init__(self, llm: Any | None = None) -> None:
        # Immutable dependency only (LLM client). Node stays stateless.
        self._llm = llm

    def _resolve(self, request_text: str, project_hint: str) -> dict[str, Any]:
        """Propose {principal, role_id, resource_path} from NL.

        Uses the injected llm when present; otherwise returns an empty triple so a
        structured caller (input_context) supplies the values in deterministic-core.
        """
        if self._llm is not None:
            # Real deployment: structured JSON completion. The service layer still
            # validates/normalises the result - the LLM never bypasses the gates.
            proposed = self._llm.resolve_binding(request_text, project_hint=project_hint)
            return {
                "principal": proposed.get("principal", ""),
                "role_id": proposed.get("role_id", ""),
                "resource_path": proposed.get("resource_path", ""),
            }
        return {"principal": "", "role_id": "", "resource_path": ""}

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Checking the request...",
            metadata={"step": "pre_process"},
        )
        user_input = state.get("user_input", "")
        input_context = state.get("input_context", {})  # read-only [C1]
        project_hint = str(input_context.get("project_id", "") or "")

        # S-2: deterministic credential/PII scan BEFORE any resolution touches the payload.
        violation = scan_for_embedded_credentials(user_input) or scan_for_embedded_credentials(str(input_context))
        if violation:
            emit_trace_event("input_parse_rejected", {"reason": "embedded_credential"}, state)
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"InputParseNode: S-2 gate rejected input - {violation}"],
            }

        # Structured callers may pass the triple directly; else the LLM resolves it.
        proposed = {
            "principal": input_context.get("principal", ""),
            "role_id": input_context.get("role_id", ""),
            "resource_path": input_context.get("resource_path", ""),
        }
        if not all(proposed.values()):
            proposed = {**proposed, **{k: v for k, v in self._resolve(user_input, project_hint).items() if v}}

        principal = normalize_principal(proposed.get("principal", ""), project_hint)
        role_id = (proposed.get("role_id", "") or "").strip()
        resource_path = (proposed.get("resource_path", "") or "").strip()

        # Ambiguous / unresolved principal -> return candidates, never guess.
        if principal is None:
            emit_trace_event("input_parse_ambiguous", {"field": "principal"}, state)
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["InputParseNode: could not resolve a fully qualified principal"],
                "resolution_candidates": to_json([proposed.get("principal", "")]),
            }
        if not validate_role_id(role_id):
            emit_trace_event("input_parse_ambiguous", {"field": "role_id"}, state)
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"InputParseNode: '{role_id}' is not a valid GCP role id (roles/...)"],
            }
        if not resource_path:
            emit_trace_event("input_parse_ambiguous", {"field": "resource_path"}, state)
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["InputParseNode: could not resolve a target resource path"],
            }

        tier = sensitivity_tier(role_id)
        emit_trace_event(
            "input_parsed",
            {"role_id": role_id, "sensitivity_tier": tier, "has_resource": bool(resource_path)},
            state,
        )
        return {
            "validated_input": user_input.strip() if isinstance(user_input, str) else user_input,
            "principal": principal,
            "role_id": role_id,
            "resource_path": resource_path,
            "sensitivity_tier": tier,
            "status": AgentStatus.SUCCESS.value,
        }

    def _extra_security_gate_input(self, state: dict[str, Any]) -> dict[str, Any]:
        """S-2 domain hook: re-verify no embedded credential slipped through at the gate boundary."""
        payload = state.get("validated_input") or state.get("user_input") or ""
        if isinstance(payload, str):
            violation = scan_for_embedded_credentials(payload)
            if violation:
                return {
                    "status": AgentStatus.ERROR.value,
                    "error_log": [f"S-2 gate: {violation}"],
                }
        return state
