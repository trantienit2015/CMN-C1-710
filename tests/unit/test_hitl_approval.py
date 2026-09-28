# CMN-C1-710 - Unit tests: HITL D6 approval path (PolicyAttachNode owner/editor tier)
#
# interrupt() requires the LangGraph runnable context, so the first-pass interrupt is
# exercised at the graph level in tests/proof_of_boundary/test_pb7_hitl_interrupt_propagation.py.
# These unit tests cover the resume branch and the HITL-disabled tier policy, which
# run without a runtime context.

from framework.schemas.agent_status import AgentStatus

from src.nodes.main_node import PolicyAttachNode
from src.schemas.state import from_json
from src.services.gcp_iam_client import GcpIamPolicyClient

ALLOWED = ["roles/owner", "roles/editor"]
RES_ALLOW = ["projects/p"]


class FakeBackend:
    def get_iam_policy(self, resource_path):
        return {"bindings": [], "etag": "etag-0"}

    def set_iam_policy(self, resource_path, policy):
        return {"etag": "etag-applied"}


def _node(hitl_enabled=True):
    return PolicyAttachNode(
        gcp_client=GcpIamPolicyClient(backend=FakeBackend()),
        allowed_roles=ALLOWED,
        resource_allowlist=RES_ALLOW,
        hitl_enabled=hitl_enabled,
    )


def _owner_state():
    return {
        "principal": "user:admin@corp.com",
        "role_id": "roles/owner",
        "resource_path": "projects/p",
        "sensitivity_tier": "owner",
        "correlation_id": "hitl-test",
    }


class TestHitlApproval:
    def test_resume_with_approval_applies_binding(self):
        """Resume: hitl_draft present (post-interrupt) + approved feedback -> binding applied."""
        st = {**_owner_state(), "hitl_draft": {"role": "roles/owner"}, "hitl_feedback": {"decision": "approved"}}
        result = _node().execute(st)
        assert result["status"] == AgentStatus.SUCCESS
        assert result["approval_status"] == "approved"
        assert from_json(result["binding_result"], {})["role"] == "roles/owner"

    def test_hitl_disabled_owner_auto_fail(self):
        """HITL disabled -> owner-tier auto-FAILs 'HITL required' (never silent approve)."""
        result = _node(hitl_enabled=False).execute(_owner_state())
        assert result["status"] == AgentStatus.ERROR
        assert result["approval_status"] == "rejected"
        assert any("HITL" in e for e in result["error_log"])

    def test_hitl_disabled_editor_auto_fail(self):
        st = {**_owner_state(), "role_id": "roles/editor", "sensitivity_tier": "editor"}
        result = _node(hitl_enabled=False).execute(st)
        assert result["status"] == AgentStatus.ERROR
