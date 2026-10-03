#!/usr/bin/env python3
"""
VibeShield Layer-1 task runner.

Executes an encrypted/encoded task payload inside the configured sandbox
backend (podman or OpenShell) and prints a JSON result to stdout.

Usage:
    echo '{"task": "..."}' | python3 scripts/sandbox_task.py --task-id run-01
    python3 scripts/sandbox_task.py --task-id run-02 --payload-file task.json \
        --backend openshell --entrypoint python3

Backend selection:
    --backend flag  >  VIBESHIELD_SANDBOX_BACKEND env  >  podman (default)

Exit codes:
    0  task succeeded (sandbox exit 0, no security block)
    1  task failed inside the sandbox
    2  runner/usage error (bad task-id, unknown backend, blocked payload)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.layer1_factory import create_sandbox, get_backend  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a task in a VibeShield Layer-1 sandbox")
    parser.add_argument("--task-id", required=True,
                        help="Task identifier [a-zA-Z0-9_-]+")
    parser.add_argument("--payload-file",
                        help="Path to payload file (default: read stdin)")
    parser.add_argument("--backend", choices=("podman", "openshell"),
                        help="Sandbox backend (default: env/VIBESHIELD_SANDBOX_BACKEND or podman)")
    parser.add_argument("--entrypoint", default="python3",
                        help="Entrypoint binary (allowlisted interpreters only)")
    parser.add_argument("--no-security-scan", action="store_true",
                        help="Disable injection/exfil scans (not recommended)")
    parser.add_argument("--egress", action="append", default=[],
                        metavar="HOST[:PORT]",
                        help="Scoped egress rule (repeatable). Requires OpenShell backend "
                             "or podman EgressRule support; ignored otherwise.")
    parser.add_argument("--env", action="append", default=[],
                        metavar="KEY=VALUE",
                        help="Env var for the workload (must match [A-Z][A-Z0-9_]*)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # Payload
    try:
        if args.payload_file:
            with open(args.payload_file) as fh:
                payload = fh.read()
        else:
            payload = sys.stdin.read()
    except OSError as exc:
        print(f"error: cannot read payload: {exc}", file=sys.stderr)
        return 2

    # Egress rules
    egress_rules = []
    for spec in args.egress:
        host, _, port = spec.partition(":")
        egress_rules.append({"host": host, "port": int(port) if port else 443})

    # Env vars
    env_vars = {}
    for kv in args.env:
        key, _, value = kv.partition("=")
        env_vars[key] = value

    # Config: reuse SandboxConfig for egress compat where supported
    from core.config import SandboxConfig
    config = SandboxConfig()

    backend = args.backend or get_backend()

    try:
        sandbox = create_sandbox(args.task_id, config=config, backend=args.backend)
        if backend == "openshell":
            result = sandbox.deploy_agent_compat(
                payload,
                entrypoint=args.entrypoint,
                egress_rules=egress_rules or None,
                env_vars=env_vars or None,
                security_scan=not args.no_security_scan,
            )
        else:
            raw = sandbox.deploy_agent(
                payload,
                entrypoint=args.entrypoint,
                egress_rules=[
                    {"host": r["host"], "port": r["port"], "protocol": "tcp"}
                    for r in egress_rules
                ] or None,
                env_vars=env_vars or None,
                security_scan=not args.no_security_scan,
            )
            # Podman SandboxResult: derive success from state/exit_code
            from types import SimpleNamespace
            result = SimpleNamespace(
                success=(raw.state.value if hasattr(raw.state, "value") else str(raw.state)) == "COMPLETED" and raw.exit_code == 0,
                exit_code=raw.exit_code,
                stdout=raw.stdout,
                stderr=raw.stderr,
                task_id=raw.task_id,
                duration_seconds=raw.duration_seconds,
            )
    except (ValueError, PermissionError) as exc:
        print(json.dumps({"ok": False, "blocked": str(exc), "backend": backend}))
        return 2

    print(json.dumps({
        "ok": bool(result.success),
        "backend": backend,
        "exit_code": result.exit_code,
        "duration_s": round(result.duration_seconds, 3),
        "task_id": result.task_id,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-2000:],
    }, indent=2))

    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
