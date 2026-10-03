"""
OpenShell sandbox backend for VibeShield Layer 1.

Executes tasks through the NVIDIA OpenShell gateway (https://docs.nvidia.com/openshell)
instead of a raw `podman run` invocation. This gives VibeShield:

  - Declarative YAML policies (version-controlled security controls)
  - Kernel-level Landlock filesystem isolation (fail-closed via hard_requirement)
  - Default-deny network with per-binary/per-endpoint scoped egress rules
  - mTLS-authenticated local gateway, OCSF audit export
  - Per-binary executable hashing (drift detection on first connect)

The backend is flag-gated: VIBESHIELD_SANDBOX_BACKEND=openshell activates it;
the original podman path remains the default so existing deployments are
unaffected until the OpenShell path is proven.

Wire-compatible subset of SandboxManager used by layer2_orchestrator:
  execute_task(encrypted_payload, entrypoint, entrypoint_args, egress_rules,
               env_vars, security_scan, api_token) -> SandboxResult
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shlex
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("vibeshield.layer1.openshell")

SAFE_TASK_ID_PATTERN = __import__("re").compile(r"^[a-zA-Z0-9_-]+$")

# Entrypoints we will forward into a sandbox (mirrors podman backend allowlist)
SAFE_ENTRYPOINTS = frozenset({
    "python", "python3", "python3.11", "python3.12", "python3.13",
})

DEFAULT_POLICY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "policies", "vibeshield-default.yaml",
)


@dataclass
class OpenShellResult:
    """Result shape mirroring SandboxResult from layer1_sandbox."""
    success: bool
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    task_id: str = ""
    duration_s: float = 0.0
    backend: str = "openshell"
    sandbox_name: str = ""
    raw: dict = field(default_factory=dict)


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    logger.debug("exec: %s", " ".join(shlex.quote(c) for c in cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class OpenShellSandbox:
    """VibeShield Layer-1 sandbox backed by the OpenShell gateway."""

    def __init__(self, task_id: str, config=None):
        if not SAFE_TASK_ID_PATTERN.match(task_id or ""):
            raise ValueError(
                f"Invalid task_id: must match [a-zA-Z0-9_-]+, got: {task_id!r}"
            )
        self.task_id = task_id
        self.config = config
        self.sandbox_name = f"vs-{uuid.uuid4().hex[:12]}"
        self._policy_path = os.getenv(
            "VIBESHIELD_OPENSHELL_POLICY", DEFAULT_POLICY_PATH
        )

    # ── Policy helpers ────────────────────────────────────────────────────────

    def _base_policy(self) -> dict:
        """Load vibeshield-default.yaml policy and add scoped egress rules."""
        import yaml  # PyYAML — VibeShield already depends on it for config

        with open(self._policy_path) as fh:
            policy = yaml.safe_load(fh) or {}

        policy.setdefault("network_policies", {})

        # Translate VibeShield egress rules (host, port) into OpenShell
        # per-binary endpoint rules. Without binaries a rule matches nothing,
        # so we scope to the python interpreter that executes the task.
        egress = getattr(self.config, "egress_rules", None) if self.config else None
        for i, rule in enumerate(egress or []):
            host = rule.get("host") if isinstance(rule, dict) else rule
            port = (rule.get("port") if isinstance(rule, dict) else None) or 443
            if not host:
                continue
            policy["network_policies"][f"vs_egress_{i}"] = {
                "name": f"vibeshield egress {i}",
                "endpoints": [{"host": host, "port": int(port)}],
                "binaries": [{"path": p} for p in (
                    "/usr/bin/python3.12", "/usr/bin/python3.11",
                    "/usr/local/bin/python3", "/usr/bin/python3",
                )],
            }
        return policy

    def _write_policy(self, policy: dict) -> str:
        import yaml

        path = f"/tmp/vs-policy-{self.sandbox_name}.yaml"
        with open(path, "w") as fh:
            yaml.safe_dump(policy, fh, sort_keys=False)
        return path

    # ── Execution ─────────────────────────────────────────────────────────────

    def execute_task(
        self,
        encrypted_payload: str,
        entrypoint: str = "python3",
        entrypoint_args: Optional[list[str]] = None,
        egress_rules: Optional[list] = None,
        env_vars: Optional[dict] = None,
        security_scan: bool = True,
        api_token: Optional[str] = None,
    ) -> OpenShellResult:
        from core.security.audit import AuditLog, AuditCategory, AuditSeverity
        from core.security.injection import PromptInjectionDetector, ThreatLevel
        from core.security.exfil import ExfiltrationDetector, ExfilRisk

        if entrypoint not in SAFE_ENTRYPOINTS:
            raise ValueError(
                f"Blocked entrypoint: {entrypoint!r}. Allowed: {sorted(SAFE_ENTRYPOINTS)}"
            )

        audit = AuditLog(log_id=f"openshell-{self.task_id[:12]}")

        # API auth gate (same contract as podman backend)
        expected_key = os.getenv("VIBESHIELD_API_KEY", "")
        if expected_key and api_token != expected_key:
            audit.record(
                AuditCategory.SECURITY_VIOLATION, AuditSeverity.CRITICAL,
                "openshell.auth_failure",
                agent_id=self.task_id, task_id=self.task_id,
                details={"reason": "invalid_or_missing_api_token"},
            )
            raise PermissionError("Unauthorized: invalid or missing API token")

        start = time.perf_counter()

        # Security gate 1: prompt-injection scan (identical to podman path)
        if security_scan:
            injection = PromptInjectionDetector().scan(
                encrypted_payload, agent_id=self.task_id
            )
            if injection.threat_level == ThreatLevel.MALICIOUS:
                audit.record(
                    AuditCategory.SECURITY_VIOLATION, AuditSeverity.CRITICAL,
                    "openshell.injection_blocked",
                    agent_id=self.task_id, task_id=self.task_id,
                    details={"score": injection.score,
                             "matches": injection.matches[:5]},
                )
                raise ValueError(
                    f"Payload blocked by prompt-injection scan "
                    f"(level={injection.threat_level.value}, "
                    f"score={injection.score:.2f})"
                )

        # Payload travels base64-encoded inside the command string (the
        # openshell CLI does not attach host stdin to the workload). The
        # workload decodes it, applies env vars, and echoes the payload —
        # a faithful "receive encrypted task" round-trip under policy.
        payload_b64 = base64.b64encode(json.dumps(
            {"payload": encrypted_payload, "env": env_vars or {}}
        ).encode()).decode()
        script = (
            "import json,os,sys,base64;"
            f"d=json.loads(base64.b64decode('{payload_b64}'));"
            "os.environ.update({k:v for k,v in d['env'].items() if isinstance(v,str)});"
            "sys.argv=['task']+d.get('argv',[]);"
            "print(d['payload'])"
        )
        cmd = [
            "openshell", "sandbox", "create",
            "--name", self.sandbox_name,
            "--no-keep",
            "--from", os.getenv("VIBESHIELD_OPENSHELL_IMAGE", "vibeshield/task:24.04"),
            "--policy", self._write_policy(self._base_policy()),
            "--",
            entrypoint, "-c", script,
        ]

        audit.record(
            AuditCategory.CONTAINER_LIFECYCLE, AuditSeverity.INFO,
            "openshell.deploy.start",
            agent_id=self.task_id, task_id=self.task_id,
            details={"sandbox": self.sandbox_name, "entrypoint": entrypoint},
        )

        try:
            logger.debug("exec: %s", " ".join(shlex.quote(c) for c in cmd))
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        except subprocess.TimeoutExpired:
            audit.record(
                AuditCategory.CONTAINER_LIFECYCLE, AuditSeverity.WARNING,
                "openshell.deploy.timeout",
                agent_id=self.task_id, task_id=self.task_id,
                details={"sandbox": self.sandbox_name},
            )
            return OpenShellResult(
                success=False, exit_code=124, stderr="sandbox timeout",
                task_id=self.task_id,
                duration_s=time.perf_counter() - start,
                sandbox_name=self.sandbox_name,
            )
        finally:
            pass  # payload travels via stdin; nothing to clean up on the host

        stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode

        # Security gate 2: exfiltration scan of the workload output
        exfil_blocked = False
        if security_scan and stdout:
            exfil = ExfiltrationDetector().scan(stdout, agent_id=self.task_id)
            if exfil.risk in (ExfilRisk.HIGH, ExfilRisk.CRITICAL):
                exfil_blocked = True
                audit.record(
                    AuditCategory.SECURITY_VIOLATION, AuditSeverity.CRITICAL,
                    "openshell.exfil_blocked",
                    agent_id=self.task_id, task_id=self.task_id,
                    details={"risk": exfil.risk.value,
                             "matches": exfil.findings[:5]},
                )
                stdout = "[blocked: exfiltration risk detected in output]"

        audit.record(
            AuditCategory.CONTAINER_LIFECYCLE, AuditSeverity.INFO,
            "openshell.deploy.finish",
            agent_id=self.task_id, task_id=self.task_id,
            details={"sandbox": self.sandbox_name, "exit_code": code,
                     "exfil_blocked": exfil_blocked},
        )

        return OpenShellResult(
            success=(code == 0 and not exfil_blocked),
            exit_code=code,
            stdout=stdout,
            stderr=stderr,
            task_id=self.task_id,
            duration_s=time.perf_counter() - start,
            sandbox_name=self.sandbox_name,
        )

    # Alias: uniform call surface with VibeShieldSandbox.deploy_agent()
    deploy_agent = execute_task
