# VibeShield Security Framework

<p align="center">
  <strong>Zero-Trust Podman Security for Autonomous AI Agent Workforces</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Podman-Rootless-blue?logo=podman" />
  <img src="https://img.shields.io/badge/Layer-1_Sandbox-orange" />
  <img src="https://img.shields.io/badge/Layer-2_Orchestration-orange" />
  <img src="https://img.shields.io/badge/Layer-3_Escrow-orange" />
  <img src="https://img.shields.io/badge/License-Apache_2.0-green" />
</p>

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=kevin046/VibeShield&type=Date)](https://star-history.com/#kevin046/VibeShield&Date)

---

## Overview

The VibeShield Security Framework provides the essential infrastructure for deploying autonomous AI agents in high-security enterprise environments. It enforces a **Zero-Trust** containerization model where agents run as unprivileged user processes, isolated by Linux namespaces and hardware-backed Trusted Execution Environments (TEE).

Built on [Podman](https://podman.io/), VibeShield eliminates the daemon-based attack surface that plagues traditional container runtimes. Every agent executes in a rootless, ephemeral container with no persistent state — cryptographically shredded after each task.

## The Three Layers

```
┌─────────────────────────────────────────────────┐
│           Layer 3: Market Engine & Escrow        │
│     Bounty settlement · Reputation (Rs) · DAO    │
├─────────────────────────────────────────────────┤
│           Layer 2: Orchestration Engine          │
│     Ping & Echo verification · Lead/Worker agents │
├─────────────────────────────────────────────────┤
│           Layer 1: Confidential Sandbox          │
│  Rootless Podman · TEE · Egress filtering · Air-gap │
└─────────────────────────────────────────────────┘
         ↕
┌─────────────────────────────────────────────────┐
│          Security Subsystem (Cross-Layer)         │
│  Seccomp · Audit Chain · Egress Proxy · Inj.     │
│  Detection · Exfil Scanning · Image Verify ·     │
│  Encrypted Workspaces                            │
└─────────────────────────────────────────────────┘
```

## Why Podman?

| Property | Traditional (Docker) | VibeShield (Podman) |
|---|---|---|
| Daemon | Root-level daemon required | Daemonless |
| Execution | Privileged by default | Rootless by default |
| Escape surface | Single point of failure | Per-container isolation |
| Memory (idle) | Baseline | 65% lower |
| Startup | ~500ms | <200ms (crun) |
| Privilege escalation | Possible via daemon socket | Not possible without root |

Podman's daemonless architecture means there is **no central process to compromise**. Each agent container is managed as a standard Linux process, systemd-integrated for lifecycle management.

## Quick Start

### Prerequisites

- Podman 4.x+ with crun
- Python 3.11+
- systemd (for quadlet integration)

```bash
# Clone the repository
git clone https://github.com/kevin046/VibeShield.git
cd VibeShield

# Install Python dependencies
pip install -r requirements.txt

# Build the base image
podman build -t vibeshield/base:latest -f Containerfile .

# Run a sandboxed agent
python -m core.layer1_sandbox --task-id demo --payload "encrypted_task_data"
```

### Orchestrate with Podman Compose

```bash
# Start the full stack (orchestrator + escrow)
podman-compose -f podman-compose.yaml up -d

# Verify all services
podman-compose -f podman-compose.yaml ps
```

### Generate Quadlet Units (systemd integration)

```bash
# Convert podman-compose to native systemd units
podman generate kube vibeshield-orchestrator | podman play kube --replace -

# Generate systemd quadlet file from a container
podman generate systemd --new --name vibeshield-orchestrator > ~/.config/systemd/user/vibeshield-orchestrator.container
systemctl --user daemon-reload
systemctl --user enable --now vibeshield-orchestrator
```

## Architecture

### Layer 1 — Confidential Sandbox

Every task executes inside a rootless Podman container:

- **`--network=none`** by default — total network isolation
- **`--cap-drop=ALL`** — all Linux capabilities removed
- **`--security-opt=no-new-privileges`** — prevents privilege escalation
- **`--tmpfs`** for workspace — no persistent disk writes
- Cryptographic shredding of keys and volumes after task completion

### Layer 2 — Orchestration & Verification

The "Ping & Echo" protocol validates agent identity in real-time:

1. **Ping** — Platform sends a diagnostic challenge with constraints (letter restrictions, word limits, logical traps)
2. **Echo** — Agent generates a real-time response; platform analyzes constraint satisfaction, latency, and grammar quality
3. **Verify** — Self-reported model is cross-checked against declared model

Confidence levels: Live Verified (95%+) | Fingerprint (~70%) | Inconclusive (Low)

### Layer 3 — Market Engine & Escrow

Bounty-based marketplace with economic guarantees:

- **Reputation scoring (Rs)** — weighted decay formula, +5% multiplier for verified agents
- **3-Agent Consensus** — dispute resolution via independent agent panels
- **Escrow settlement** — funds held until deliverable is verified
- **Snapshot audit** — outputs captured from the sandbox, never read from live files

## Project Structure

```
VibeShield/
├── README.md                    # This file
├── SECURITY.md                  # Vulnerability disclosure & reporting
├── LICENSE                      # Apache-2.0
├── Containerfile                # Rootless OCI-compliant image
├── podman-compose.yaml          # Multi-agent orchestration
├── requirements.txt             # Python dependencies
├── core/
│   ├── __init__.py
│   ├── layer1_sandbox.py        # Podman rootless isolation & TEE logic
│   ├── layer2_orchestrator.py   # Behavioral verification (Ping & Echo)
│   ├── layer3_escrow.py         # Economic settlement & Rs scoring
│   ├── config.py                # Framework configuration
│   └── security/                # Security subsystem
│       ├── __init__.py          # Package exports
│       ├── seccomp.py           # Syscall filtering profiles
│       ├── audit.py             # Tamper-evident hash-chained logging
│       ├── egress.py            # DNS allowlisting & connection proxy
│       ├── injection.py         # Prompt injection detection
│       ├── exfil.py             # Output exfiltration detection
│       ├── image_verify.py      # Container image integrity verification
│       └── workspace.py         # Encrypted tmpfs workspace management
├── api/
│   ├── __init__.py
│   └── commands.py              # Standardized agent command protocol
├── tests/
│   ├── __init__.py
│   ├── test_sandbox.py
│   ├── test_orchestrator.py
│   ├── test_escrow.py
│   └── test_security.py         # Security subsystem tests (59 tests)
└── scripts/
    ├── install.sh               # Quick install script
    └── quadlet_setup.sh         # systemd quadlet generator
```

## Agent Command Protocol

Agents interact with the VibeShield infrastructure through standardized commands:

| Command | Purpose |
|---|---|
| `HEARTBEAT` | Prove the agent is still running |
| `SIGNAL_COMPLETE` | Notify task completion |
| `REQUEST_MEMORY` | Request extended context window |
| `WEB_SEARCH` | Request web search capability |
| `REQUEST_DATA` | Pull data from external APIs |
| `ESCROW_RELEASE` | Request payment release |
| `STATE_SYNC` | Sync state with orchestrator |

## Security Posture

VibeShield is designed around **defense in depth** — multiple independent security layers that each provide protection even if another is compromised:

### Sandbox Isolation (Layer 1)
- No root access required at any layer
- Network isolation by default (opt-in egress through audited proxy)
- Ephemeral containers — keys destroyed after each task, not just deleted
- No daemon socket — eliminates the most common container escape vector
- SELinux/AppArmor integration for mandatory access control

### Kernel-Level Restrictions
- **Seccomp profiles** — default-deny syscall filtering; only ~60 syscalls permitted out of 400+
- Always-blocked: `ptrace`, `mount`, `userfaultfd`, `keyctl`, `bpf`, `unshare`, `kexec`
- Three presets: `minimal` (no network), `compute` (CPU-bound), `network` (audited egress only)
- Audit mode for testing before enforcement

### Tamper-Evident Audit Chain
- SHA-256 hash chaining — every log entry cryptographically linked to the previous
- Tamper detection: any modification (insert, delete, change) breaks the chain
- JSONL export for external analysis and long-term archival
- Queryable by agent, category, severity, and time range

### Egress Proxy & DNS Allowlisting
- Default-deny: no outbound connection without explicit domain allowlisting
- Wildcard support (`*.googleapis.com`) for API domains
- Per-agent rate limiting (requests/minute)
- Request size limits to prevent data exfiltration via large payloads
- Full connection audit trail (host, port, protocol, bytes, decision)

### Input Security
- **Prompt injection detection** — scans all agent inputs before processing
- 14 high-confidence malicious patterns (instruction override, jailbreak, role hijacking)
- 7 medium-confidence suspicious patterns (system prompt probing, hidden instructions)
- Obfuscation detection: zero-width chars, control characters, base64-encoded payloads
- Any malicious match → immediate block

### Output Security
- **Exfiltration detection** — scans all agent outputs before delivery
- Secret pattern matching: API keys, tokens, private keys, passwords, AWS credentials
- PII detection: SSN, credit cards, emails, IP addresses
- Shannon entropy analysis (sliding window) — detects encrypted/compressed data smuggling
- Covert channel detection: hex/unicode escapes, long base64 strings, binary encoding
- Size anomaly detection: flags outputs significantly larger than expected

### Container Integrity
- **Image verification** — SHA-256 digest pinning for all deployed images
- Optional Cosign/Sigstore signature verification
- Digest mismatch → deployment blocked, possible tampering alert

### Encrypted Workspaces
- tmpfs-backed (RAM-only, never touches disk)
- Ephemeral encryption keys (generated per-task, shredded after use)
- Multi-pass secure wipe (3-pass random overwrite) on teardown
- Size-bounded to prevent resource exhaustion

## Enterprise Use Cases

- **Deep Research** — SEC filings, legal docs, market intelligence in isolated sandboxes
- **Mass Outreach** — Email and social campaigns with identity proxy and anti-spam gating
- **Operational Automation** — Invoice triage, cross-platform sync with ephemeral memory
- **Compliance Monitoring** — Regulatory change tracking via sandboxed crawlers

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Community

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
- [Discussions](https://github.com/kevin046/VibeShield/discussions)
- [Issues](https://github.com/kevin046/VibeShield/issues)

## License

Apache-2.0 — see [LICENSE](LICENSE).

---

**VibeShield** | Vibedrift Inc.
