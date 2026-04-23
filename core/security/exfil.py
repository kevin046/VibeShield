"""
Output Exfiltration Detection — Scan agent outputs for data leakage.

Detects attempts by agents to exfiltrate sensitive data through:
- High entropy payloads (encrypted/compressed data being smuggled out)
- Pattern matching for secrets, API keys, credentials, PII
- Covert channel detection (steganography-like encoding in outputs)
- Size anomaly detection (outputs larger than expected for the task)

This runs as a post-processing filter on all agent outputs before delivery.
"""

import re
import math
import logging
from dataclasses import dataclass
from typing import Optional
from enum import Enum

logger = logging.getLogger("vibeshield.security.exfil")


class ExfilRisk(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ExfilResult:
    """Result of an exfiltration scan."""
    risk: ExfilRisk
    score: float  # 0.0 to 1.0
    entropy: float  # Shannon entropy of the output
    findings: list[str]
    recommendation: str = ""


class ExfiltrationDetector:
    """
    Scans agent outputs for potential data exfiltration.

    Uses Shannon entropy analysis, regex pattern matching, and
    size heuristics to flag suspicious outputs.
    """

    # Patterns that indicate leaked secrets
    SECRET_PATTERNS = [
        (r"(?i)-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Private key detected"),
        (r"(?i)(sk|pk|rk)-(live|test|prod)_[a-zA-Z0-9]{20,}", "Stripe API key"),
        (r"(?i)ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
        (r"(?i)gho_[a-zA-Z0-9]{36}", "GitHub OAuth token"),
        (r"(?i)ghs_[a-zA-Z0-9]{36}", "GitHub App token"),
        (r"(?i)ghu_[a-zA-Z0-9]{36}", "GitHub User token"),
        (r"(?i)xox[bpas]-[a-zA-Z0-9-]+", "Slack token"),
        (r"(?i)AKIA[A-Z0-9]{16}", "AWS Access Key"),
        (r"(?i)AIza[a-zA-Z0-9_-]{35}", "Google API key"),
        (r"(?i)nvapi-[a-zA-Z0-9_-]{30,}", "NVIDIA API key"),
        (r"(?i)hf_[a-zA-Z0-9]{30,}", "HuggingFace token"),
        (r"(?i)sbp_[a-zA-Z0-9]{30,}", "Supabase token"),
        (r"(?i)password\s*[=:]\s*['\"]?[^\s'\"]{8,}", "Password in output"),
        (r"(?i)secret\s*[=:]\s*['\"]?[^\s'\"]{8,}", "Secret in output"),
        (r"(?i)token\s*[=:]\s*['\"]?[^\s'\"]{20,}", "Token in output"),
    ]

    # PII patterns
    PII_PATTERNS = [
        (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "SSN-like pattern"),
        (r"\b\d{16}\b", "Credit card number pattern"),
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address"),
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP address"),
    ]

    # Covert channel patterns
    COVERT_PATTERNS = [
        (r"(?i)\\x[0-9a-f]{2}", "Hex escape sequence (potential covert channel)"),
        (r"(?i)\\u[0-9a-f]{4}", "Unicode escape sequence (potential covert channel)"),
        (r"(?i)\b[A-Za-z0-9+/]{100,}={0,2}\b", "Long base64 string (possible encoding)"),
        (r"(?i)\b[01]{200,}\b", "Long binary string (possible covert encoding)"),
    ]

    def __init__(
        self,
        max_entropy_threshold: float = 4.5,
        max_output_size: int = 100000,
        entropy_window_size: int = 200,
    ):
        self.max_entropy_threshold = max_entropy_threshold
        self.max_output_size = max_output_size
        self.entropy_window_size = entropy_window_size

        self._secret_re = [(re.compile(p), desc) for p, desc in self.SECRET_PATTERNS]
        self._pii_re = [(re.compile(p), desc) for p, desc in self.PII_PATTERNS]
        self._covert_re = [(re.compile(p), desc) for p, desc in self.COVERT_PATTERNS]

    def scan(
        self,
        output: str,
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        expected_size: Optional[int] = None,
    ) -> ExfilResult:
        """
        Scan an agent output for potential data exfiltration.

        Args:
            output: The agent's output text
            agent_id: Agent that produced the output
            task_id: Task context
            expected_size: Expected output size for size anomaly detection

        Returns:
            ExfilResult with risk level and findings
        """
        if not output:
            return ExfilResult(ExfilRisk.NONE, 0.0, 0.0, [])

        findings = []
        score = 0.0

        # 1. Check for leaked secrets (highest severity)
        for pattern, desc in self._secret_re:
            if pattern.search(output):
                findings.append(f"[SECRET] {desc}")
                # Private keys, Stripe keys → CRITICAL immediately
                if "Private key" in desc or "Stripe" in desc:
                    score += 0.7
                else:
                    score += 0.5

        # 2. Check for PII
        for pattern, desc in self._pii_re:
            if pattern.search(output):
                findings.append(f"[PII] {desc}")
                score += 0.2

        # 3. Check for covert channels
        for pattern, desc in self._covert_re:
            if pattern.search(output):
                findings.append(f"[COVERT] {desc}")
                score += 0.2

        # 4. Shannon entropy analysis (sliding window)
        max_entropy = self._max_shannon_entropy(output)
        if max_entropy > self.max_entropy_threshold:
            findings.append(
                f"[ENTROPY] High entropy detected: {max_entropy:.2f} "
                f"(threshold: {self.max_entropy_threshold})"
            )
            score += 0.3

        # 5. Size anomaly detection
        if expected_size and len(output) > expected_size * 3:
            findings.append(
                f"[SIZE] Output {len(output)} chars, expected ~{expected_size} "
                f"({len(output) / max(expected_size, 1):.1f}x larger)"
            )
            score += 0.2

        # 6. Absolute size limit
        if len(output) > self.max_output_size:
            findings.append(
                f"[SIZE] Output exceeds maximum ({len(output)} > {self.max_output_size})"
            )
            score += 0.3

        # Cap and determine risk
        score = min(score, 1.0)
        risk = self._score_to_risk(score)

        if risk != ExfilRisk.NONE:
            log_fn = logger.warning if risk in (ExfilRisk.HIGH, ExfilRisk.CRITICAL) else logger.info
            log_fn(
                f"Exfiltration risk: {risk.value} (score={score:.2f}) | "
                f"agent={agent_id or 'unknown'} | entropy={max_entropy:.2f} | "
                f"findings={len(findings)}"
            )

        return ExfilResult(
            risk=risk,
            score=round(score, 3),
            entropy=round(max_entropy, 3),
            findings=findings,
            recommendation=self._recommendation(risk, findings),
        )

    def _max_shannon_entropy(self, text: str) -> float:
        """Calculate the maximum Shannon entropy in any sliding window."""
        window = self.entropy_window_size
        max_ent = 0.0

        for i in range(max(0, len(text) - window + 1)):
            segment = text[i:i + window]
            ent = self._shannon_entropy(segment)
            max_ent = max(max_ent, ent)

        return max_ent

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a text string."""
        if not text:
            return 0.0

        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def _score_to_risk(score: float) -> ExfilRisk:
        if score >= 0.7:
            return ExfilRisk.CRITICAL
        elif score >= 0.5:
            return ExfilRisk.HIGH
        elif score >= 0.3:
            return ExfilRisk.MEDIUM
        elif score >= 0.1:
            return ExfilRisk.LOW
        return ExfilRisk.NONE

    @staticmethod
    def _recommendation(risk: ExfilRisk, findings: list[str]) -> str:
        if risk == ExfilRisk.CRITICAL:
            return "BLOCK: Output contains leaked secrets or highly suspicious patterns. Do not deliver."
        elif risk == ExfilRisk.HIGH:
            return "REVIEW: Output contains suspicious patterns. Human review recommended before delivery."
        elif risk == ExfilRisk.MEDIUM:
            return "MONITOR: Output has some suspicious characteristics. Log for audit."
        elif risk == ExfilRisk.LOW:
            return "LOG: Minor anomalies detected. No action required."
        return "CLEAR: No exfiltration indicators detected."
