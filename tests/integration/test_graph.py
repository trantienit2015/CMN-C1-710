# CMN-C1-710 - Integration test: full graph compile + invoke

import json

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import Graph
from src.services.gcp_iam_client import GcpIamPolicyClient


class FakeBackend:
    def __init__(self):
        self._policy = {"bindings": [], "etag": "etag-0"}

    def get_iam_policy(self, resource_path):
        return {"bindings": list(self._policy["bindings"]), "etag": self._policy["etag"]}

    def set_iam_policy(self, resource_path, policy):
        self._policy = {"bindings": policy["bindings"], "etag": "etag-applied"}
        return {"etag": "etag-applied"}


def _agent():
    return Graph(
        config={
            "gcp_client": GcpIamPolicyClient(backend=FakeBackend()),
            "allowed_roles": ["roles/storage.objectViewer"],
            "resource_allowlist": ["projects/p"],
            "hitl_enabled": False,
            "max_retry": 1,
        }
    )


class TestAgentIntegration:
    def test_full_pipeline_success_viewer(self):
        """Full backbone: viewer-tier binding applied end-to-end, >=5 nodes."""
        agent = _agent()
        agent.compile()

        ctx = InvocationContext(
            session_id="itest-1", caller_trust_level=TrustLevel.INTERNAL, caller_id="itest-caller"
        )
        result = agent.invoke(
            "grant storage.objectViewer to x on billing bucket",
            ctx=ctx,
            input_context={
                "principal": "service-account-x@p.iam.gserviceaccount.com",
                "role_id": "roles/storage.objectViewer",
                "resource_path": "projects/p",
            },
        )

        assert result["status"] == "success"
        assert len(result.get("node_history", [])) >= 5

        output = result.get("output", "")
        assert isinstance(output, str)
        payload = json.loads(output)
        assert payload["binding"]["role"] == "roles/storage.objectViewer"
        assert payload["binding"]["etag"] == "etag-applied"
        assert payload["audit_metadata"]["isms_control"] == "A.9.2.2"

    def test_whitelist_block_yields_error(self):
        """Role outside allowlist -> pipeline ends error/cancelled, no binding."""
        agent = _agent()
        agent.compile()

        ctx = InvocationContext(
            session_id="itest-2", caller_trust_level=TrustLevel.INTERNAL, caller_id="itest-caller"
        )
        result = agent.invoke(
            "grant owner",
            ctx=ctx,
            input_context={
                "principal": "user:admin@corp.com",
                "role_id": "roles/owner",
                "resource_path": "projects/p",
            },
        )
        assert result["status"] in ("error", "cancelled")

    def test_low_trust_caller_denied(self):
        """S-1: ANONYMOUS caller cannot invoke this INTERNAL-gated agent."""
        agent = _agent()
        agent.compile()

        ctx = InvocationContext(
            session_id="itest-3", caller_trust_level=TrustLevel.ANONYMOUS, caller_id="anon"
        )
        result = agent.invoke(
            "grant viewer",
            ctx=ctx,
            input_context={
                "principal": "user:a@b.com",
                "role_id": "roles/storage.objectViewer",
                "resource_path": "projects/p",
            },
        )
        assert result["status"] in ("error", "cancelled")
