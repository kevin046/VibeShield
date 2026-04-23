---
description: Run a security review on the VibeShield codebase using Anthropic's methodology
---

Review the entire codebase for security vulnerabilities. Focus on:

## HIGH-PRIORITY CATEGORIES

1. **Command injection** — subprocess.run with shell=True, unsanitized strings in commands
2. **Path traversal** — user-controlled paths in file operations without validation
3. **Insecure deserialization** — pickle, yaml.load, eval, exec with untrusted data
4. **Hardcoded secrets** — API keys, tokens, passwords, private keys in code
5. **Improper input validation** — missing validation on public API inputs (agent_id, task_id, payloads)
6. **Information exposure** — sensitive data in logs, debug output, error messages to clients
7. **Cryptographic issues** — weak algorithms, predictable random (use secrets not random), insufficient key lengths

## REVIEW METHODOLOGY

For each file in `core/`, `core/security/`, `api/`, and `scripts/`:
1. Read the full file
2. Identify all inputs from external sources (function parameters, file reads, network data, env vars)
3. Trace how each input flows through the code
4. Check if inputs are validated before use
5. Check if outputs could leak sensitive information

## REPORTING FORMAT

For each finding:
- **File**:path (line number)
- **Severity**: HIGH / MEDIUM / LOW
- **Category**: e.g., command_injection, path_traversal
- **Description**: What the vulnerability is
- **Exploit scenario**: How it could be abused
- **Fix**: Specific code change to remediate

## RULES

- Only report issues with confidence > 0.7 (real vulnerabilities)
- Skip DoS, rate limiting, and style issues
- Check ALL files, not just the first few
- Do NOT modify any files — this is a read-only review
