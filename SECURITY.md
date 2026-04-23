# Security Policy

## Supported Versions

The VibeShield Security Framework follows semantic versioning. Security patches are applied to the latest release branch.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in the VibeShield Security Framework, please report it responsibly.

### Do NOT open a public GitHub issue.

Instead, report vulnerabilities via:

1. **GitHub Security Advisories**: Use the [Security tab](https://github.com/kevin046/VibeShield/security/advisories/new) on this repository (recommended)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any proof-of-concept code (encrypted preferred)

### Response Timeline

| Severity | Initial Response | Patch Target |
|---|---|---|
| Critical (RCE, data exfiltration) | 24 hours | 48 hours |
| High (privilege escalation) | 48 hours | 7 days |
| Medium (information disclosure) | 72 hours | 14 days |
| Low (best practice violation) | 1 week | Next release |

### What to Expect

1. We will acknowledge receipt within the timeline above
2. We will investigate and determine severity
3. We will coordinate a disclosure timeline with you
4. Credit will be given in the release notes (unless anonymity is requested)

## Security Architecture

The VibeShield Security Framework is designed with the following threat model:

### In Scope
- Container escape via Podman misconfiguration
- Network egress from sandboxed agents
- Data leakage through shared resources (CPU side-channels, memory)
- Compromised agent logic attempting privilege escalation
- Supply chain attacks via malicious base images

### Out of Scope
- Physical access to host hardware
- Kernel-level exploits (mitigated by keeping host updated)
- Social engineering of operators

### Trust Boundaries

```
Untrusted Zone          Semi-Trusted Zone         Trusted Zone
(Agent Code)           (Podman Runtime)          (Host + Escrow)
┌──────────┐          ┌──────────────┐          ┌──────────────┐
│ Agent LLM│──network──│ Rootless Pod │──socket──│ Escrow Engine │
│ Tools    │  isolate  │ crun runtime │  quadlet │ Rs Scoring   │
│ Payload  │  drop all │ seccomp      │  systemd │ Settlement   │
└──────────┘  caps     └──────────────┘          └──────────────┘
```

## Supply Chain

- Base images are built from scratch using `FROM scratch` + minimal package install
- All dependencies are pinned with hash verification in `requirements.txt`
- Containerfile uses `COPY --chown` to prevent privilege escalation during build
- No multi-stage build secrets leak (build arguments are not persisted)
