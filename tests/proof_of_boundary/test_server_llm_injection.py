# The standalone entry point must import and construct with no LLM credential present —
# deploy-stg provisions none — and its caller-auth boundary must never let the external
# bearer token reach INTERNAL. This template builds no LLM client at the entry point, so
# the blueprint's LLM-construction case does not apply and is omitted here.

import importlib


class TestServerBootsWithoutAnthropicKey:
    def test_server_imports_and_app_constructs_with_no_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        import src.api.server as server

        importlib.reload(server)

        assert server.app is not None
        assert server.agent is not None


class TestStandaloneTrustPromotion:
    def test_external_bearer_never_promotes_to_internal(self):
        import src.api.server as server
        from framework.schemas.trust_level import TrustLevel

        assert server._resolve_standalone_trust(
            TrustLevel.ANONYMOUS, "Bearer external", "external", "runner"
        ) is TrustLevel.VERIFIED_EXTERNAL

    def test_runner_bearer_promotes_to_internal(self):
        import src.api.server as server
        from framework.schemas.trust_level import TrustLevel

        assert server._resolve_standalone_trust(
            TrustLevel.ANONYMOUS, "Bearer runner", "external", "runner"
        ) is TrustLevel.INTERNAL

    def test_wrong_or_missing_bearer_is_rejected_when_auth_is_enabled(self):
        import pytest
        import src.api.server as server
        from fastapi import HTTPException
        from framework.schemas.trust_level import TrustLevel

        for authorization in ("", "Bearer wrong"):
            with pytest.raises(HTTPException) as exc:
                server._resolve_standalone_trust(TrustLevel.ANONYMOUS, authorization, "external", "runner")
            assert exc.value.status_code == 401
