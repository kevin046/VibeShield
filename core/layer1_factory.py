"""
Layer-1 backend factory — picks the sandbox implementation per deployment.

  VIBESHIELD_SANDBOX_BACKEND=openshell  → OpenShellSandbox (NVIDIA OpenShell
                                          gateway: Landlock hard-requirement,
                                          declarative YAML policy, per-binary
                                          network rules, OCSF audit export)
  VIBESHIELD_SANDBOX_BACKEND=podman     → VibeShieldSandbox (original rootless
                                          Podman path; DEFAULT)

Both classes implement the same call surface:

    sb = create_sandbox(task_id, config)
    result = sb.deploy_agent(encrypted_payload, entrypoint=..., ...)

Result objects both carry: success, exit_code, stdout, stderr, task_id,
duration_s. The OpenShell result additionally carries backend/sandbox_name;
the podman result carries its own extra fields. Callers relying on
SandboxResult-specific attributes should use `asdict()`-style access guarded
by getattr, or request the podman backend explicitly.
"""
from __future__ import annotations

import os
from typing import Optional

from core.config import SandboxConfig

DEFAULT_BACKEND = "podman"


def get_backend() -> str:
    """Active Layer-1 backend name ('podman' or 'openshell')."""
    backend = os.getenv("VIBESHIELD_SANDBOX_BACKEND", DEFAULT_BACKEND).strip().lower()
    if backend not in ("podman", "openshell"):
        raise ValueError(
            f"Unknown VIBESHIELD_SANDBOX_BACKEND={backend!r} "
            "(expected 'podman' or 'openshell')"
        )
    return backend


def create_sandbox(
    task_id: str,
    config: Optional[SandboxConfig] = None,
    backend: Optional[str] = None,
):
    """Construct the Layer-1 sandbox for `task_id`.

    Args:
        task_id: [a-zA-Z0-9_-]+ task identifier (validated by both backends).
        config: SandboxConfig; egress_rules are honored by both backends.
        backend: override; defaults to VIBESHIELD_SANDBOX_BACKEND env var,
                 then 'podman'.

    Raises:
        ValueError: on unknown backend name or invalid task_id (from the
                    backend constructor).
    """
    chosen = backend or get_backend()
    if chosen == "openshell":
        from core.layer1_openshell import OpenShellSandbox
        return OpenShellSandbox(task_id, config=config)

    from core.layer1_sandbox import VibeShieldSandbox
    return VibeShieldSandbox(task_id, config=config)
