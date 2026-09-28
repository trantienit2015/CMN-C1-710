# PB-7: HITL interrupt propagation (templates with hitl.enabled: true).
#
# Verifies interrupt() fired inside PolicyAttachNode.execute() raises GraphInterrupt,
# the signal propagates through BaseNode.__call__() and is NOT caught by the
# application error boundary (status is NOT set to error). We drive the compiled
# graph (with a checkpointer) and assert the invoke suspends with AWAITING_HUMAN
# rather than resolving to error.

from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from langgraph.checkpoint.memory import InMemorySaver

from src.graph.graph import Graph
from src.services.gcp_iam_client import GcpIamPolicyClient


class _FakeBackend:
    def get_iam_policy(self, resource_path):
        return {"bindings": [], "etag": "etag-0"}

    def set_iam_policy(self, resource_path, policy):
        return {"etag": "etag-applied"}


def _hitl_agent():
    agent = Graph(
        config={
            "gcp_client": GcpIamPolicyClient(backend=_FakeBackend()),
            "allowed_roles": ["roles/owner"],
            "resource_allowlist": ["projects/p"],
            "hitl_enabled": True,
            "memory_enabled": True,
            "max_retry": 1,
        }
    )
    agent.compile(checkpointer=InMemorySaver())
    return agent


class TestHitlInterruptPropagation:
    def test_interrupt_suspends_not_error(self):
        agent = _hitl_agent()
        ctx = InvocationContext(session_id="pb7", caller_trust_level=TrustLevel.INTERNAL, caller_id="sre")
        result = agent.invoke(
            "grant owner on project",
            ctx=ctx,
            input_context={
                "principal": "user:admin@corp.com",
                "role_id": "roles/owner",
                "resource_path": "projects/p",
            },
        )
        status = result.get("status")
        assert status in (
            AgentStatus.AWAITING_HUMAN,
            AgentStatus.AWAITING_HUMAN.value,
        ), f"expected AWAITING_HUMAN, got {status}: {result.get('error_log')}"
        assert status not in (AgentStatus.ERROR, AgentStatus.ERROR.value)
