# VibeShield Security Framework

**Zero-Trust Podman Security for Autonomous AI Agent Workforces**

Kevin Lin — Vibedrift Inc.

**Version 1.0 — April 2026**

---

## Abstract

Autonomous AI agents that execute code, access files, and make network requests represent a fundamentally new security challenge. Traditional container security — designed for microservices with known workloads — fails when the *workload itself is an adversarial intelligence*. Malicious prompts can instruct agents to exfiltrate secrets, escape sandboxes, or persist beyond their intended scope.

VibeShield is a defense-in-depth security framework purpose-built for autonomous AI agent execution. It provides 7 integrated security modules — seccomp sandboxing, hash-chained audit logging, egress filtering, prompt injection detection, exfiltration scanning, container image verification, and encrypted workspace isolation — all built on rootless Podman containers with zero daemon attack surface. With 116 tests across all modules and Apache 2.0 licensing, VibeShield is designed for enterprise deployment of AI agent workforces.

---

## 1. The Problem

### 1.1 Why Traditional Container Security Fails

Docker and traditional container runtimes were designed for microservices: predictable workloads with known entry points, known dependencies, and known behaviors. AI agents are fundamentally different:

| Challenge | Microservices | AI Agents |
|-----------|--------------|-----------|
| **Workload** | Known at deploy time | Generated at runtime by an LLM |
| **Trust boundary** | Code reviewed before deploy | Code generated *inside* the container |
| **Network access** | Known API dependencies | Agent decides what APIs to call |
| **Data access** | Schema-defined database queries | Agent reads/writes arbitrary files |
| **Persistence** | Stateless replicas | Agent may attempt to persist state |
| **Input** | HTTP requests with known schemas | Natural language — inherently ambiguous |

An LLM-powered agent can be instructed to: read `/etc/shadow`, exfiltrate environment variables via DNS, encode secrets in base64 output, spawn shells, mount filesystems, or write persistent cron jobs. Traditional container security assumes the workload is *cooperative*. AI agents must be treated as *potentially adversarial at all times*.

### 1.2 The Daemon Attack Surface

Docker's architecture requires a root-level daemon (`dockerd`) with a Unix socket (`/var/run/docker.sock`). This daemon is:

- **A single point of failure** — compromise the daemon, compromise every container
- **A privilege escalation vector** — any user with socket access can create privileged containers
- **A persistent process** — runs even when no containers are active, increasing attack window
- **A resource consumer** — Docker's idle memory usage is ~65% higher than Podman's

VibeShield eliminates this entirely by using Podman's daemonless architecture.

---

## 2. Architecture

### 2.1 The Three Layers

VibeShield enforces security through a layered model:

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

**Layer 1 (Confidential Sandbox)** — Kernel-level isolation. Each agent runs in a rootless Podman container with no network access, no persistent storage, and no Linux capabilities. Workspaces are tmpfs-backed and cryptographically shredded after each task.

**Layer 2 (Orchestration & Verification)** — Behavioral monitoring. The "Ping & Echo" protocol validates agent identity in real-time using diagnostic challenges with constraints (letter restrictions, word limits, logical traps). Confidence levels range from Live Verified (95%+) to Inconclusive.

**Layer 3 (Market Engine & Escrow)** — Economic guarantees. Bounty-based marketplace with reputation scoring (Rs), 3-agent consensus dispute resolution, and escrow settlement that holds funds until deliverables are verified from sandbox snapshots.

### 2.2 Why Podman

| Property | Traditional (Docker) | VibeShield (Podman) |
|----------|---------------------|---------------------|
| Daemon | Root-level daemon required | Daemonless |
| Execution | Privileged by default | Rootless by default |
| Escape surface | Single point of failure | Per-container isolation |
| Memory (idle) | Baseline | 65% lower |
| Startup | ~500ms | <200ms (crun) |
| Privilege escalation | Possible via daemon socket | Not possible without root |

Podman's daemonless architecture means there is **no central process to compromise**. Each agent container is managed as a standard Linux process, systemd-integrated for lifecycle management. Podman is also OCI-compliant and supports Docker-compatible CLI syntax, making migration straightforward.

---

## 3. Security Modules

### 3.1 Seccomp Profile (`seccomp.py`)

**Threat:** Syscall-based sandbox escape or privilege escalation via kernel interfaces.

**Defense:** Seccomp (Secure Computing Mode) restricts which system calls a container process can invoke. VibeShield starts from Podman's proven default profile (tested across thousands of workloads) and adds explicit `SCMP_ACT_KILL` rules for dangerous syscalls.

**26 syscalls blocked (KILL rules):**

| Category | Syscalls |
|----------|----------|
| Kernel modules | `init_module`, `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`, `bpf`, `reboot` |
| Process control | `ptrace`, `process_vm_readv`, `process_vm_writev` |
| Key management | `keyctl`, `request_key`, `add_key` |
| Filesystem | `mount`, `mount_setattr`, `move_mount`, `umount2`, `pivot_root`, `open_tree`, `fspick`, `fsopen`, `fsconfig`, `fsmount` |
| Memory | `swapon`, `swapoff`, `perf_event_open` |

**Presets:**
- `minimal` — No network syscalls permitted (default, recommended)
- `compute` — CPU-bound workloads with limited I/O
- `network` — Audited egress through the EgressProxy only

**Design lesson:** Do NOT build a default-deny allowlist from scratch. The number of syscalls needed for even basic process execution is large and architecture-dependent. Start from Podman's tested default and only ADD kill rules.

### 3.2 Audit Log (`audit.py`)

**Threat:** Tampering with execution logs to cover up malicious activity.

**Defense:** SHA-256 hash-chained append-only audit trail. Every log entry includes a `previous_hash` field that cryptographically links it to the preceding entry.

```json
{
  "timestamp": "2026-04-25T19:00:00Z",
  "severity": "INFO",
  "category": "EXECUTION",
  "event": "Task started: demo_001",
  "agent_id": "a6008da3",
  "hash": "sha256:abc123...",
  "previous_hash": "sha256:def456..."
}
```

**Properties:**
- Any modification (insert, delete, change) breaks the chain — detectable by rehashing
- JSONL format for external analysis and long-term archival
- Queryable by agent ID, category, severity, and time range
- Exported to `/tmp/clawmolt_audit/audit.jsonl` on shutdown
- Records execution start/complete, security violations, and verification results

### 3.3 Egress Proxy (`egress.py`)

**Threat:** Agent exfiltrates data via DNS, HTTP, or other network protocols.

**Defense:** Default-deny egress filtering with domain allowlisting. By default, containers run with `--network=none` — total network isolation. When network access is required, it passes through the EgressProxy with:

- **Domain allowlist** — Only explicitly whitelisted domains are reachable
- **Wildcard support** — `*.googleapis.com` for API domains
- **Per-agent rate limiting** — Requests per minute per agent
- **Request size limits** — Prevents data exfiltration via large payloads
- **Connection audit trail** — Host, port, protocol, bytes transferred, allow/deny decision
- **Trusted API presets** — Pre-configured rules for common LLM providers (OpenAI, Anthropic, Google)

### 3.4 Prompt Injection Detector (`injection.py`)

**Threat:** Malicious user sends adversarial prompts that cause the agent to bypass security controls or execute unintended actions.

**Defense:** Scans all task prompts before they reach the agent. Uses pattern matching against known adversarial techniques:

**14 high-confidence patterns (score ≥ 0.7 → BLOCKED):**
- Instruction override (`ignore previous instructions`, `forget your role`)
- Jailbreak attempts (`DAN`, `developer mode`, `you are now ChatGPT`)
- Role hijacking (`pretend you are`, `act as an administrator`)
- Exfil URLs (`https://evil.com/log?data=`)
- System prompt extraction (`repeat your system prompt`, `what are your instructions`)

**7 medium-confidence patterns (score 0.3–0.7 → WARNED):**
- System prompt probing (`what rules do you follow?`)
- Hidden instructions in code blocks
- Multi-turn manipulation chains

**Obfuscation detection:**
- Zero-width characters (U+200B, U+FEFF)
- Control characters and escape sequences
- Base64-encoded payloads
- Unicode homoglyph substitution

**Design:** A risk score ≥ 0.7 returns HTTP 422 (blocked). Score 0.3–0.7 allows execution but flags the session for monitoring.

### 3.5 Exfiltration Detector (`exfil.py`)

**Threat:** Agent includes stolen secrets, PII, or confidential data in its output.

**Defense:** Scans all agent outputs before delivery to the user. Uses multiple detection strategies:

| Strategy | What it catches |
|----------|----------------|
| Secret pattern matching | API keys, tokens, private keys, passwords, AWS credentials |
| PII detection | SSN, credit cards, emails, IP addresses, phone numbers |
| Shannon entropy analysis | Encrypted/compressed data smuggling (sliding window) |
| Covert channel detection | Hex/unicode escapes, long base64 strings, binary encoding |
| Size anomaly detection | Outputs significantly larger than expected for the task |

**Risk levels:**
- `LOW` — Minor anomalies, logged only
- `MEDIUM` — Suspicious patterns found, broadcast warning to monitoring
- `HIGH` — Clear exfiltration attempt, alert operator + audit log
- `CRITICAL` — Confirmed secret/credential leak, immediate action required

### 3.6 Image Verifier (`image_verify.py`)

**Threat:** Supply chain attack via compromised or tampered container images.

**Defense:** SHA-256 digest pinning for all deployed container images. Before each execution, the image digest is verified against the expected value.

- **Digest pinning** — `localhost/vibeshield/clawmolt@sha256:abc123...` — exact byte-level verification
- **Optional Cosign/Sigstore** — Cryptographic signature verification for images from external registries
- **Digest mismatch** → Deployment blocked + tampering alert raised
- **Base image** — `localhost/vibeshield/clawmolt:latest` built from verified Containerfile

### 3.7 Workspace Manager (`workspace.py`)

**Threat:** Agent persists data across tasks, escapes via filesystem, or leaves artifacts for other agents.

**Defense:** Ephemeral workspace per execution with RAM-only storage:

- **tmpfs-backed** — Data exists only in RAM, never written to disk
- **Per-task isolation** — Each execution gets a clean workspace directory
- **Sandbox file staging** — User-uploaded files are copied in; results are copied out; the workspace is then wiped
- **Secure wipe** — 3-pass random overwrite on teardown (or `shutil.rmtree` with root fallback for container-owned files)
- **Size-bounded** — Configurable maximum workspace size to prevent resource exhaustion
- **Root file cleanup** — Container processes (running as different UID) may create root-owned files; cleanup requires `sudo rm -rf`

---

## 4. Execution Pipeline

The complete security pipeline for a single agent task:

```
1. Task Prompt Received
       ↓
2. Prompt Injection Scan (injection.py)
   → Score ≥ 0.7 → BLOCKED (422)
       ↓
3. Workspace Created (workspace.py)
   → tmpfs mount, files copied in
       ↓
4. Image Verified (image_verify.py)
   → SHA-256 digest check
       ↓
5. Container Launched (Podman + seccomp.py)
   → Rootless, cap-drop ALL, network=none
   → Resource limits: RAM, CPU quota, PID limit
       ↓
6. Agent Executes (inside container)
   → Output streamed via session file
       ↓
7. Output Scanned (exfil.py)
   → Secrets, PII, entropy, covert channels
   → HIGH/CRITICAL → audit + alert
       ↓
8. Results Copied Out (workspace.py)
   → Snapshotted to DB, never read from live files
       ↓
9. Workspace Wiped (workspace.py)
   → Secure wipe, tmpfs unmount
       ↓
10. Audit Entry Written (audit.py)
    → Hash-chained, JSONL appended
```

Each step is independently enforced — failure of one layer does not compromise the others.

---

## 5. Container Configuration

### 5.1 Podman Command Structure

```bash
podman run --rm --init \
  --memory 4096m \
  --cap-drop ALL \
  --cap-add CAP_DAC_OVERRIDE,CAP_FSETID \
  --security-opt "seccomp=/path/to/profile.json" \
  --pids-limit 256 \
  --network none \
  --mount type=bind,source=/workspace,target=/home/sandbox \
  -e CLAW_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  -e HOME=/home/sandbox \
  localhost/vibeshield/clawmolt:latest \
  --model <model> \
  --output-format json \
  --allow-broad-cwd \
  "<task_prompt>"
```

**Key flags:**

| Flag | Purpose |
|------|---------|
| `--init` | Catatonit PID 1 — reaps zombie processes |
| `--cap-drop ALL` | Remove all Linux capabilities |
| `--cap-add CAP_DAC_OVERRIDE` | File permission override for bind-mounted workspace |
| `--security-opt seccomp=...` | Custom hardened seccomp profile |
| `--pids-limit 256` | Prevent fork bombs |
| `--network none` | Total network isolation (default) |
| `--memory 4096m` | RAM limit (dynamically adjusted by ResourceGovernor) |
| `--rm` | Auto-remove container after exit |

### 5.2 Dynamic Resource Governance

The ResourceGovernor monitors host CPU/RAM in real-time via `/proc/meminfo` and `/proc/stat`, and dynamically adjusts container pool size and per-container limits every 15 seconds:

- **Pool budget:** `(free_ram - 3GB_reserve) × 0.85_safety`
- **Per-container RAM:** 512MB–4096MB (auto-scaled)
- **Per-container CPU:** 15%–80% quota (auto-scaled)
- **Max concurrent:** 1–20 containers (auto-scaled based on queue depth)

This eliminates the need for manual tuning while ensuring the host remains stable under load.

---

## 6. Testing

VibeShield includes **116 tests** covering all 7 security modules:

| Module | Tests | Coverage |
|--------|-------|----------|
| Seccomp Profile | ~20 | Profile generation, validation, hardened presets |
| Audit Log | ~15 | Hash chaining, tampering detection, JSONL export |
| Egress Proxy | ~12 | Allowlist, rate limiting, audit trail |
| Injection Detection | ~18 | High/medium patterns, obfuscation, scoring |
| Exfiltration Detection | ~15 | Secret matching, entropy, PII, size anomaly |
| Image Verification | ~8 | Digest pinning, mismatch detection |
| Workspace Manager | ~12 | Create, copy, wipe, size limits |
| Integration | ~16 | Full pipeline, container lifecycle |

All tests run without Docker/Podman (mocked container operations) for CI reliability.

---

## 7. Enterprise Use Cases

**Deep Research** — SEC filings, legal documents, and market intelligence processed in isolated sandboxes. Each research task runs in a clean environment with no access to previous task data. Network access is granted only to approved financial data APIs through the EgressProxy.

**Mass Outreach** — Email and social media campaigns executed with identity proxy and anti-spam gating. Prompt injection detection prevents adversarial inputs from hijacking campaign agents. Output scanning ensures no PII leaks in generated messages.

**Operational Automation** — Invoice triage, cross-platform synchronization, and data processing with ephemeral memory. Workspace isolation ensures each task starts with a clean slate. Encrypted tmpfs storage means sensitive financial data never touches disk.

**Compliance Monitoring** — Regulatory change tracking via sandboxed web crawlers. Audit logging provides a complete, tamper-evident chain of custody for all agent actions — essential for regulated industries.

---

## 8. Comparison with Existing Systems

| System | Isolation | Audit | Injection | Exfil | Image Verify | Open Source |
|--------|-----------|-------|-----------|-------|-------------|-------------|
| Docker + AppArmor | Good | None | None | None | Optional | Yes |
| gVisor | Strong | None | None | None | Optional | Yes |
| Kata Containers | VM-level | None | None | None | Optional | Yes |
| Firecracker | VM-level | None | None | None | Optional | Yes |
| VibeShield | Strong (rootless Podman) | SHA-256 chain | 21 patterns | 5 strategies | SHA-256 pinning | Yes (Apache 2.0) |

VibeShield's differentiation is not in the isolation layer (Podman provides excellent sandboxing) but in the **cross-layer security subsystem** — the audit chain, input/output scanning, and image verification that other systems lack entirely. Container isolation alone does not protect against prompt injection or data exfiltration through legitimate output channels.

---

## 9. Limitations and Future Work

### 9.1 Current Limitations

1. **No hardware TEE integration.** The framework references TEE (Trusted Execution Environments) in its architecture but currently relies on software-level isolation only. Future work should integrate AMD SEV-SNP or Intel TDX for hardware-enforced memory encryption.

2. **Pattern-based detection has blind spots.** The prompt injection and exfiltration detectors use static pattern matching. Sophisticated adversaries can craft novel attacks that evade known patterns. A learned detection model (e.g., a small transformer trained on adversarial examples) would improve robustness.

3. **No multi-host orchestration.** All security enforcement happens on a single host. Distributed agent deployments across multiple machines require a centralized policy server and attestation protocol.

4. **Resource governor is host-level only.** The Dynamic ResourceGovernor monitors a single host. Multi-node deployments need cluster-level resource coordination.

### 9.2 Planned Improvements

1. **Hardware TEE integration** — AMD SEV-SNP and Intel TDX support for hardware-enforced memory encryption of agent workspaces.

2. **Learned threat detection** — Fine-tune a small transformer model on adversarial prompt/injection examples to replace pattern-based detection.

3. **Policy-as-Code** — Rego-based policy engine (similar to OPA) for declarative security rules that can be versioned and audited.

4. **Distributed attestation** — gRPC-based attestation protocol for multi-host deployments with hardware root of trust.

5. **Real-time monitoring dashboard** — Web UI for live audit log streaming, resource usage, and threat alerting.

---

## 10. Conclusion

VibeShield addresses a security gap that grows more critical with every deployment of autonomous AI agents: the lack of a purpose-built, defense-in-depth security framework for LLM-powered execution environments. By combining rootless Podman isolation, hash-chained audit trails, multi-strategy input/output scanning, and cryptographically verified container images, VibeShield provides enterprise-grade security for the most demanding AI agent workloads — without sacrificing the performance and flexibility that makes containers attractive in the first place.

The framework is fully open source under Apache 2.0, with 116 tests ensuring reliability. It runs on standard Linux infrastructure — no special hardware, no proprietary dependencies, no vendor lock-in.

As AI agents become more capable and more autonomous, the attack surface they present will only grow. VibeShield provides the security foundation that enterprises need to deploy AI agents with confidence.

---

**GitHub:** [github.com/kevin046/VibeShield](https://github.com/kevin046/VibeShield)
**License:** Apache 2.0
**Issues:** [github.com/kevin046/VibeShield/issues](https://github.com/kevin046/VibeShield/issues)

**VibeShield** | Vibedrift Inc.
