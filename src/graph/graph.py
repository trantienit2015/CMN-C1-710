"""AgentCore Platform v1.0 - CMN-C1-710 GCPIAMPolicyAttachAgent graph.

Cat 1 - single technical capability (NL -> GCP IAM policy binding attach),
generic and use-case-agnostic. Flat 3-slot AgentBaseGraph pipeline (NOT a Cat 2
GraphNode/inner-subgraph composition):

  START -> initialize -> pre_process -> main -> {route} -> post_process -> finalize -> END
                                      \\_ (RETRY, max 3) _/ pre_process

  pre_process  = Step 1-2 InputParse    (S-1 INTERNAL + S-2 credential scan +
                                          LLM three-way resolution)
  main         = Step 3-5 PolicyAttach  (WhitelistCheck hard block + ApprovalGate
                                          HITL D6 + etag-guarded setIamPolicy + S-4)
  post_process = Step 6 OutputValidate  (S-3 credential redaction + output contract)

HITL: when config `hitl.enabled` is true, owner/editor-tier bindings pause via
interrupt() in PolicyAttachNode (requires memory_enabled + max_hitl in agent.yaml).
A caller running unattended (GraphNode / gateway) sets state["hitl_allowed"]=False;
the interrupt is then skipped and the privileged tier fails closed instead of
deadlocking the pipeline.
"""

from framework.graph.agent_base_graph import AgentBaseGraph

from src.nodes.main_node import PolicyAttachNode
from src.nodes.post_process_node import OutputValidateNode
from src.nodes.pre_process_node import InputParseNode
from src.schemas.state import State


class Graph(AgentBaseGraph):
    """GCP IAM policy-attach agent (NL -> governed setIamPolicy binding)."""

    @property
    def name(self) -> str:
        return "cmn-c1-710"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode

        llm = self.config.get("llm")
        gcp_client = self.config.get("gcp_client")
        allowed_roles = self.config.get("allowed_roles", [])
        resource_allowlist = self.config.get("resource_allowlist", [])
        hitl_enabled = bool(self.config.get("hitl_enabled", False))

        self._nodes["pre_process"] = InputParseNode(llm=llm)
        self._nodes["main"] = PolicyAttachNode(
            gcp_client=gcp_client,
            allowed_roles=allowed_roles,
            resource_allowlist=resource_allowlist,
            hitl_enabled=hitl_enabled,
        )
        self._nodes["post_process"] = OutputValidateNode()
