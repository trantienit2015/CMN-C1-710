# CMN-C1-710 - Unit tests: PolicyAttachNode (main slot)

import inspect

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.main_node import PolicyAttachNode
from src.schemas.state import from_json
from src.services.gcp_iam_client import ConflictError, GcpIamPolicyClient

ALLOWED = ["roles/storage.objectViewer", "roles/editor"]
RES_ALLOW = ["projects/p"]


class FakeBackend:
    """In-memory getIamPolicy/setIamPolicy backend."""

    def __init__(self, conflict_times: int = 0):
        self._policy = {"bindings": [], "etag": "etag-0"}
        self._conflict_times = conflict_times
        self._n = 0

    def get_iam_policy(self, resource_path):
        return {"bindings": list(self._policy["bindings"]), "etag": self._policy["etag"]}

    def set_iam_policy(self, resource_path, policy):
        if self._n < self._conflict_times:
            self._n += 1
            raise ConflictError("etag mismatch")
        self._policy = {"bindings": policy["bindings"], "etag": "etag-applied"}
        return {"etag": "etag-applied"}


def _client(conflict_times=0):
    return GcpIamPolicyClient(backend=FakeBackend(conflict_times=conflict_times), max_retry=1)


def _viewer_state():
    return {
        "principal": "serviceAccount:x@p.iam.gserviceaccount.com",
        "role_id": "roles/storage.objectViewer",
        "resource_path": "projects/p",
        "sensitivity_tier": "viewer",
    }


class TestPolicyAttachNode:
    def test_trust_level_is_internal(self):
        assert PolicyAttachNode.required_trust_level == TrustLevel.INTERNAL

    def test_success_viewer_no_hitl(self):
        """Success: viewer tier -> no HITL -> etag write applied."""
        node = PolicyAttachNode(gcp_client=_client(), allowed_roles=ALLOWED, resource_allowlist=RES_ALLOW)
        result = node.execute(_viewer_state())
        assert result["status"] == AgentStatus.SUCCESS
        assert result["allowlist_verdict"] == "pass"
        assert result["applied_etag"] == "etag-applied"
        binding = from_json(result["binding_result"], {})
        assert binding["role"] == "roles/storage.objectViewer"

    def test_whitelist_hard_block_role(self):
        """Step 3: role not in allowlist -> hard block ERROR, no write."""
        node = PolicyAttachNode(gcp_client=_client(), allowed_roles=["roles/viewer"], resource_allowlist=RES_ALLOW)
        result = node.execute(_viewer_state())
        assert result["status"] == AgentStatus.ERROR
        assert result["allowlist_verdict"] == "fail"

    def test_whitelist_hard_block_resource(self):
        """Step 3: resource outside allowlist -> hard block ERROR."""
        node = PolicyAttachNode(gcp_client=_client(), allowed_roles=ALLOWED, resource_allowlist=["projects/other"])
        result = node.execute(_viewer_state())
        assert result["status"] == AgentStatus.ERROR
        assert result["allowlist_verdict"] == "fail"

    def test_empty_allowlist_fails_closed(self):
        """Step 3: empty allowlist -> fail-closed (no default-allow)."""
        node = PolicyAttachNode(gcp_client=_client(), allowed_roles=[], resource_allowlist=[])
        result = node.execute(_viewer_state())
        assert result["status"] == AgentStatus.ERROR

    def test_owner_tier_hitl_disabled_auto_fail(self):
        """Step 4: owner tier + HITL disabled -> auto-FAIL 'HITL required', never silent approve."""
        st = {**_viewer_state(), "role_id": "roles/owner", "sensitivity_tier": "owner"}
        node = PolicyAttachNode(
            gcp_client=_client(),
            allowed_roles=["roles/owner"],
            resource_allowlist=RES_ALLOW,
            hitl_enabled=False,
        )
        result = node.execute(st)
        assert result["status"] == AgentStatus.ERROR
        assert result["approval_status"] == "rejected"
        assert any("HITL" in e for e in result["error_log"])

    def test_owner_tier_hitl_allowed_false_no_interrupt(self):
        """Step 4 guard: hitl_allowed=False (automated pipeline) -> interrupt() is NOT
        reached (no deadlock) and the privileged tier fails closed."""
        st = {
            **_viewer_state(),
            "role_id": "roles/owner",
            "sensitivity_tier": "owner",
            "hitl_allowed": False,
        }
        node = PolicyAttachNode(
            gcp_client=_client(),
            allowed_roles=["roles/owner"],
            resource_allowlist=RES_ALLOW,
            hitl_enabled=True,
        )
        # Must return normally: an unguarded interrupt() would raise GraphInterrupt here.
        result = node.execute(st)
        assert result["status"] == AgentStatus.ERROR.value
        assert result["approval_status"] == "rejected"
        assert any("hitl_allowed is false" in e for e in result["error_log"])

    def test_owner_tier_hitl_allowed_default_still_interrupts(self, monkeypatch):
        """Step 4 guard: hitl_allowed absent -> defaults to True -> interrupt() is still
        reached, so the guard does not silently disable HITL for interactive callers.
        interrupt() is patched because a bare execute() runs outside a LangGraph runnable
        context; PB-7 covers the real GraphInterrupt propagation through the compiled graph.
        """
        import src.nodes.main_node as main_node

        calls = []
        monkeypatch.setattr(main_node, "interrupt", lambda payload: calls.append(payload) or "approve")

        st = {**_viewer_state(), "role_id": "roles/owner", "sensitivity_tier": "owner"}
        node = PolicyAttachNode(
            gcp_client=_client(),
            allowed_roles=["roles/owner"],
            resource_allowlist=RES_ALLOW,
            hitl_enabled=True,
        )
        result = node.execute(st)
        assert len(calls) == 1, "interrupt() must still fire when hitl_allowed is not set"
        assert result["status"] == AgentStatus.SUCCESS.value

    def test_etag_conflict_retry_then_success(self):
        """Step 5: one 409 conflict -> single re-read + retry -> success."""
        node = PolicyAttachNode(
            gcp_client=_client(conflict_times=1), allowed_roles=ALLOWED, resource_allowlist=RES_ALLOW
        )
        result = node.execute(_viewer_state())
        assert result["status"] == AgentStatus.SUCCESS

    def test_etag_conflict_exhausted_errors(self):
        """Step 5: conflict beyond retry budget -> ERROR (no blind overwrite)."""
        node = PolicyAttachNode(
            gcp_client=_client(conflict_times=5), allowed_roles=ALLOWED, resource_allowlist=RES_ALLOW
        )
        result = node.execute(_viewer_state())
        assert result["status"] == AgentStatus.ERROR

    def test_upstream_error_short_circuits(self):
        node = PolicyAttachNode(gcp_client=_client(), allowed_roles=ALLOWED, resource_allowlist=RES_ALLOW)
        result = node.execute({"status": AgentStatus.ERROR})
        assert result["status"] == AgentStatus.ERROR

    def test_execute_signature_no_invoke_impl(self):
        """The node defines execute(self, state) and does not define _invoke_impl()."""
        sig = inspect.signature(PolicyAttachNode.execute)
        params = list(sig.parameters.keys())
        assert params[1] == "state"
        assert "_invoke_impl" not in PolicyAttachNode.__dict__

    def test_insufficient_trust_rejected_via_call(self):
        # S-1: existing test_trust_level_is_internal only asserted the static class attribute —
        # it never exercised the actual reject behavior of BaseNode.__call__()'s trust gate.
        # This test calls node(state), not .execute(state), so the real gate runs.
        node = PolicyAttachNode(gcp_client=_client(), allowed_roles=ALLOWED, resource_allowlist=RES_ALLOW)
        state = {**_viewer_state(), "caller_trust_level": TrustLevel.ANONYMOUS.value}
        result = node(state)
        assert str(result["status"]).lower().endswith("error")
        assert any("trust gate denied" in msg.lower() for msg in result.get("error_log", []))

    def test_sufficient_trust_succeeds_via_call(self):
        node = PolicyAttachNode(gcp_client=_client(), allowed_roles=ALLOWED, resource_allowlist=RES_ALLOW)
        state = {**_viewer_state(), "caller_trust_level": TrustLevel.INTERNAL.value}
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
