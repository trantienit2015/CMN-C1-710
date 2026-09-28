"""The Marketplace entry point must carry the same concrete identity as the HTTP entry point.

An empty or defaulted agent_name/namespace sends the Marketplace path to a different secret
location than the HTTP path, which only shows up as a missing secret at run time.
"""

import ast
import pathlib

import yaml

import cli

_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _server_identity() -> tuple[str, str] | None:
    """Return the (namespace, agent_name) src/api/server.py hands to secrets_factory."""
    tree = ast.parse((_ROOT / "src" / "api" / "server.py").read_text(encoding="utf-8"))
    consts = {
        target.id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "secrets_factory":
            found = {}
            for kw in node.keywords:
                if isinstance(kw.value, ast.Constant):
                    found[kw.arg] = kw.value.value
                elif isinstance(kw.value, ast.Name) and kw.value.id in consts:
                    found[kw.arg] = consts[kw.value.id]
            if "namespace" in found and "agent_name" in found:
                return found["namespace"], found["agent_name"]
    return None


def test_identity_is_concrete():
    assert cli._AGENT_NAME, "agent_name must not be empty"
    assert cli._NAMESPACE, "namespace must not be empty"
    assert cli._NAMESPACE != "default", "the runner default would scope secrets to another agent"


def test_identity_matches_the_http_entry_point_or_the_manifest():
    server = _server_identity()
    if server is not None:
        assert (cli._NAMESPACE, cli._AGENT_NAME) == server
        return
    manifest = yaml.safe_load((_ROOT / "config" / "agent.yaml").read_text(encoding="utf-8"))
    assert cli._NAMESPACE == manifest["namespace"]
    assert cli._AGENT_NAME == str(manifest["id"]).lower()


def test_runner_call_uses_the_constants():
    source = (_ROOT / "cli.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "run_agent_marketplace":
            passed = {kw.arg: kw.value for kw in node.keywords}
            assert isinstance(passed["agent_name"], ast.Name) and passed["agent_name"].id == "_AGENT_NAME"
            assert isinstance(passed["namespace"], ast.Name) and passed["namespace"].id == "_NAMESPACE"
            return
    raise AssertionError("cli.py does not call run_agent_marketplace")
