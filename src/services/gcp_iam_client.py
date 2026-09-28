"""AgentCore Platform v1.0 - CMN-C1-710 domain service layer.

Deterministic domain logic for the GCP IAM policy-attach agent:
  - S-2 embedded-credential scan on the caller-supplied request (regex, not LLM)
  - three-way NL resolution helpers (principal / role id / resource path)
  - role -> sensitivity tier mapping
  - role + resource double allowlist check (deterministic hard block)
  - etag-guarded read-modify-write client over GCP Cloud Resource Manager
    (getIamPolicy -> append binding -> setIamPolicy) with a fake/injectable
    backend so the template stays deterministic-core (no google-cloud dep)
  - output sanitisation: strip SA-key / raw-policy-dump patterns, preserve the
    confirmed binding summary + audit reference

No agenticstar imports. No business logic lives in nodes - nodes call these
pure functions/classes and own only the FunctionNode/state/security plumbing.
"""

from __future__ import annotations

import re
from typing import Any

# -- S-2: embedded-credential detection (deterministic regex, NOT an LLM check) --

# GCP service-account key JSON, bearer/JWT tokens, generic credential fields, and
# My Number (Japanese My Number, 12 consecutive digits) embedded in the request.
_SA_PRIVATE_KEY_RE = re.compile(r'"private_key"\s*:', re.IGNORECASE)
_SA_KEY_BLOCK_RE = re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")
_BEARER_JWT_RE = re.compile(r"(Bearer\s+[A-Za-z0-9._-]{10,}|eyJ[A-Za-z0-9._-]{10,})")
_CRED_FIELD_RE = re.compile(r'"(?:password|credential|client_secret)"\s*:', re.IGNORECASE)
_MYNUMBER_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")


def scan_for_embedded_credentials(payload: str) -> str | None:
    """Return a violation reason string if payload embeds credentials/PII, else None.

    Deterministic regex scan - static analysis, not an LLM judgment. Principal
    emails and project ids are legitimate payload and are intentionally NOT matched.
    """
    if not payload:
        return None
    if _SA_PRIVATE_KEY_RE.search(payload) or _SA_KEY_BLOCK_RE.search(payload):
        return "embedded GCP service-account private key detected in request payload"
    if _BEARER_JWT_RE.search(payload):
        return "embedded bearer token / JWT detected in request payload"
    if _CRED_FIELD_RE.search(payload):
        return "embedded credential field (password/client_secret) detected in request payload"
    if _MYNUMBER_RE.search(payload):
        return "embedded My Number (12-digit) pattern detected in request payload"
    return None


# -- Step 1: three-way NL resolution (deterministic helpers) ---------------------
#
# The LLM in InputParseNode proposes {principal, role_id, resource_path}. These
# helpers deterministically normalise / validate that proposal against GCP naming
# rules and the known role catalog - the LLM never invents an unrecognised role.

# Minimal predefined-role catalog with sensitivity tiers. A real deployment fetches
# the live catalog via the GCP IAM API; this deterministic-core map covers the
# common predefined roles and is extended from config (allowed_roles) at runtime.
_ROLE_TIER: dict[str, str] = {
    "roles/owner": "owner",
    "roles/editor": "editor",
    "roles/viewer": "viewer",
    "roles/storage.admin": "editor",
    "roles/storage.objectAdmin": "editor",
    "roles/storage.objectViewer": "viewer",
    "roles/bigquery.dataViewer": "viewer",
    "roles/bigquery.dataEditor": "editor",
    "roles/iam.serviceAccountUser": "editor",
}

_PRINCIPAL_PREFIXES = ("user:", "serviceAccount:", "group:", "domain:")
_ROLE_RE = re.compile(r"^roles/[A-Za-z0-9][A-Za-z0-9._-]*$")


def normalize_principal(raw: str, project_hint: str = "") -> str | None:
    """Return a fully qualified principal or None if it cannot be formed safely.

    Accepts an already-qualified principal (user:.../serviceAccount:...) as-is; a bare
    email is qualified as user: / serviceAccount: by shape (...gserviceaccount.com ->
    serviceAccount). Ambiguous/empty -> None (caller returns candidates, never guesses).
    """
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith(_PRINCIPAL_PREFIXES):
        return raw
    if "@" in raw:
        if raw.endswith("gserviceaccount.com"):
            return f"serviceAccount:{raw}"
        return f"user:{raw}"
    return None


def validate_role_id(role_id: str) -> bool:
    """Deterministic role-id shape check (roles/...) - never invent an unknown role."""
    return bool(role_id) and bool(_ROLE_RE.match(role_id.strip()))


def sensitivity_tier(role_id: str) -> str:
    """Map a role id to its sensitivity tier. Unknown roles default to the highest
    tier ('owner') so an unrecognised role is treated as maximally sensitive."""
    return _ROLE_TIER.get((role_id or "").strip(), "owner")


# -- Step 2: role + resource double allowlist (deterministic hard block) ---------


def check_allowlists(
    role_id: str,
    resource_path: str,
    allowed_roles: list[str],
    resource_allowlist: list[str],
) -> tuple[bool, str]:
    """Return (ok, reason). Both allowlists must be non-empty and both must match.

    Empty/unset allowlist -> fail-fast (no default-allow): an unconfigured agent must
    never grant. Resource match is prefix-based (allowlist entry is a path prefix).
    """
    if not allowed_roles:
        return False, "allowed_roles is empty/unset - fail-closed (no default-allow)"
    if not resource_allowlist:
        return False, "resource allowlist is empty/unset - fail-closed (no default-allow)"
    if role_id not in allowed_roles:
        return False, f"role '{role_id}' is not in allowed_roles"
    if not any(resource_path == p or resource_path.startswith(p.rstrip("/") + "/") for p in resource_allowlist):
        return False, f"resource '{resource_path}' is outside the resource allowlist"
    return True, "role and resource both allowlisted"


# -- Step 4: etag-guarded read-modify-write over Cloud Resource Manager ----------


class GcpIamError(Exception):
    """Raised when the GCP IAM policy read-modify-write fails after one retry."""


class GcpIamPolicyClient:
    """Etag-guarded read-modify-write wrapper over Cloud Resource Manager
     getIamPolicy / setIamPolicy.

     A real deployment injects a google-cloud-resource-manager-backed implementation
     via the graph config; tests inject a fake backend. This class has no default
     google-cloud dependency so the template stays deterministic-core
    . The injected `backend` must expose:
         get_iam_policy(resource_path) -> {"bindings": [...], "etag": str}
         set_iam_policy(resource_path, policy) -> {"etag": str}
     and may raise `ConflictError` (mapped to a 409 re-read+retry).
    """

    def __init__(self, backend: Any | None = None, max_retry: int = 1) -> None:
        self._backend = backend
        self._max_retry = max_retry

    def attach_binding(self, resource_path: str, principal: str, role_id: str) -> dict[str, Any]:
        """Read-modify-write a single binding with etag concurrency control.

        409 (concurrent edit) -> single re-read + retry, then GcpIamError (no
        blind overwrite). Returns {principal, role, resource, etag}.
        """
        if self._backend is None:
            raise GcpIamError("no GCP IAM backend configured (deterministic-core: inject a backend)")

        attempts = 0
        while True:
            policy = self._backend.get_iam_policy(resource_path)
            bindings = list(policy.get("bindings", []))
            _append_member(bindings, role_id, principal)
            new_policy = {"bindings": bindings, "etag": policy.get("etag", "")}
            try:
                applied = self._backend.set_iam_policy(resource_path, new_policy)
                return {
                    "principal": principal,
                    "role": role_id,
                    "resource": resource_path,
                    "etag": applied.get("etag", ""),
                }
            except _conflict_types() as exc:  # noqa: PERF203 - retry path
                attempts += 1
                if attempts > self._max_retry:
                    raise GcpIamError(f"setIamPolicy conflict after {attempts} attempts: {exc}") from exc
                # loop -> single re-read + retry


def _append_member(bindings: list[dict[str, Any]], role_id: str, principal: str) -> None:
    """Append principal to the role's binding (create the binding if absent), idempotently."""
    for b in bindings:
        if b.get("role") == role_id:
            members = b.setdefault("members", [])
            if principal not in members:
                members.append(principal)
            return
    bindings.append({"role": role_id, "members": [principal]})


class ConflictError(Exception):
    """Backend-raised concurrent-edit signal (maps to GCP 409)."""


def _conflict_types() -> tuple[type[BaseException], ...]:
    """Conflict exception types to catch for the 409 retry path."""
    return (ConflictError,)


# -- Step 6: output sanitisation (S-3 preservation variant) ----------------------

_OUTPUT_SA_KEY_RE = re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----", re.DOTALL)
_OUTPUT_JWT_RE = re.compile(r"eyJ[A-Za-z0-9._-]{10,}")


def redact_sensitive_output(text: str) -> tuple[str, bool]:
    """Redact SA-key blocks / JWTs from output while preserving binding summary.

    Returns (possibly_redacted_text, was_redacted).
    """
    if not text:
        return text, False
    redacted = _OUTPUT_SA_KEY_RE.sub("[REDACTED_SA_KEY]", text)
    redacted = _OUTPUT_JWT_RE.sub("[REDACTED_TOKEN]", redacted)
    return redacted, redacted != text


def build_output_contract(
    binding_result: dict[str, Any] | None,
    approval_status: str,
    scan_ts: str,
) -> dict[str, Any]:
    """Assemble the locked output contract returned to the caller."""
    binding = binding_result or {}
    return {
        "binding": {
            "principal": binding.get("principal", ""),
            "role": binding.get("role", ""),
            "resource": binding.get("resource", ""),
            "etag": binding.get("etag", ""),
        },
        "approval_status": approval_status,
        "audit_metadata": {
            "scan_ts": scan_ts,
            "isms_control": "A.9.2.2",
            "evidence": "NISC DevSecOps IAM mutation record",
        },
    }
