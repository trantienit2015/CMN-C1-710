# CMN-C1-710 - Unit tests: OutputValidateNode (post_process slot)

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.nodes.post_process_node import OutputValidateNode
from src.schemas.state import from_json, to_json


class TestOutputValidateNode:
    def setup_method(self):
        self.node = OutputValidateNode()

    def test_trust_level_declared(self):
        assert OutputValidateNode.required_trust_level == TrustLevel.ANONYMOUS

    def test_success_builds_output_contract(self):
        binding = {
            "principal": "serviceAccount:x@p.iam.gserviceaccount.com",
            "role": "roles/storage.objectViewer",
            "resource": "projects/p",
            "etag": "etag-applied",
        }
        state = {"binding_result": to_json(binding), "approval_status": "auto"}
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        payload = from_json(result["result"], {})
        assert payload["binding"]["role"] == "roles/storage.objectViewer"
        assert payload["audit_metadata"]["isms_control"] == "A.9.2.2"

    def test_upstream_error_short_circuits(self):
        result = self.node.execute({"status": AgentStatus.ERROR})
        assert result["status"] == AgentStatus.ERROR

    def test_extra_security_gate_output_redacts_sa_key(self):
        """S-3 domain hook redacts a leaked SA key block, preserves the rest, never raises."""
        leaked = "binding ok -----BEGIN PRIVATE KEY-----SECRET-----END PRIVATE KEY----- done"
        out = self.node._extra_security_gate_output({"result": leaked})
        assert "[REDACTED_SA_KEY]" in out["result"]
        assert "SECRET" not in out["result"]

    def test_extra_security_gate_output_passthrough_clean(self):
        state = {"result": '{"binding": {"role": "roles/viewer"}}'}
        out = self.node._extra_security_gate_output(state)
        assert out is state
