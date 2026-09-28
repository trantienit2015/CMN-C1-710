# CMN-C1-710 - Unit tests: InputParseNode (pre_process slot)

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.pre_process_node import InputParseNode
from src.schemas.state import from_json


class TestInputParseNode:
    def setup_method(self):
        self.node = InputParseNode()

    def test_trust_level_is_internal(self):
        """S-1: privileged IAM write -> INTERNAL, not the default ANONYMOUS."""
        assert InputParseNode.required_trust_level == TrustLevel.INTERNAL

    def test_success_structured_input(self):
        """Success path: structured caller supplies the resolved triple."""
        state = {
            "user_input": "grant viewer on billing bucket",
            "input_context": {
                "principal": "service-account-x@proj.iam.gserviceaccount.com",
                "role_id": "roles/storage.objectViewer",
                "resource_path": "projects/p/buckets/billing",
            },
        }
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert result["principal"] == "serviceAccount:service-account-x@proj.iam.gserviceaccount.com"
        assert result["role_id"] == "roles/storage.objectViewer"
        assert result["sensitivity_tier"] == "viewer"

    def test_embedded_credential_rejected(self):
        """S-2: embedded SA private key -> auto-reject (ERROR), not advisory."""
        state = {
            "user_input": 'grant with key {"private_key": "-----BEGIN PRIVATE KEY-----abc"}',
            "input_context": {},
        }
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.ERROR
        assert any("S-2 gate" in e for e in result["error_log"])

    def test_mynumber_rejected(self):
        """S-2: embedded ---- (12-digit) -> reject."""
        state = {"user_input": "grant to 123456789012 owner", "input_context": {}}
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.ERROR

    def test_ambiguous_principal_returns_candidates_no_guess(self):
        """Edge: unresolvable principal -> ERROR + candidates, never guessed."""
        state = {
            "user_input": "grant something",
            "input_context": {
                "principal": "not-an-email",
                "role_id": "roles/viewer",
                "resource_path": "projects/p",
            },
        }
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.ERROR
        assert "resolution_candidates" in result
        assert from_json(result["resolution_candidates"], []) == ["not-an-email"]

    def test_invalid_role_rejected(self):
        """Edge: role that is not roles/... shape -> ERROR (never invented)."""
        state = {
            "user_input": "grant admin",
            "input_context": {
                "principal": "user:a@b.com",
                "role_id": "superadmin",
                "resource_path": "projects/p",
            },
        }
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.ERROR

    def test_extra_security_gate_input_blocks_leaked_credential(self):
        """S-2 domain hook returns ERROR dict (never raises) on credential in state."""
        state = {"validated_input": "Bearer abcdefghijklmnop"}
        out = self.node._extra_security_gate_input(state)
        assert out["status"] == AgentStatus.ERROR

    def test_extra_security_gate_input_passthrough_clean(self):
        """S-2 hook returns state unchanged when clean."""
        state = {"validated_input": "grant viewer on bucket"}
        out = self.node._extra_security_gate_input(state)
        assert out is state

    def test_insufficient_trust_rejected_via_call(self):
        # S-1: existing test_trust_level_is_internal only asserted the static class attribute —
        # it never exercised the actual reject behavior of BaseNode.__call__()'s trust gate.
        # This test calls node(state), not .execute(state), so the real gate runs.
        state = {
            "user_input": "grant viewer on billing bucket",
            "input_context": {
                "principal": "service-account-x@proj.iam.gserviceaccount.com",
                "role_id": "roles/storage.objectViewer",
                "resource_path": "projects/p/buckets/billing",
            },
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        result = self.node(state)
        assert str(result["status"]).lower().endswith("error")
        assert any("trust gate denied" in msg.lower() for msg in result.get("error_log", []))

    def test_sufficient_trust_succeeds_via_call(self):
        state = {
            "user_input": "grant viewer on billing bucket",
            "input_context": {
                "principal": "service-account-x@proj.iam.gserviceaccount.com",
                "role_id": "roles/storage.objectViewer",
                "resource_path": "projects/p/buckets/billing",
            },
            "caller_trust_level": TrustLevel.INTERNAL.value,
        }
        result = self.node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
