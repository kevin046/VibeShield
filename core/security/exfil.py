"""
Output Exfiltration Detection — Scan agent outputs for data leakage.

Detects attempts by agents to exfiltrate sensitive data through:
- High entropy payloads (encrypted/compressed data being smuggled out)
- Pattern matching for secrets, API keys, credentials, PII
- Covert channel detection (steganography-like encoding in outputs)
- Size anomaly detection (outputs larger than expected for the task)
- Data fingerprint scanning (does output contain sensitive context data?)
- Network data egress monitoring

This runs as a post-processing filter on all agent outputs before delivery.
"""

import re
import math
import hashlib
import logging
from dataclasses import dataclass
from typing import Optional, Union
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

    Uses Shannon entropy analysis, regex pattern matching,
    size heuristics, and optional data fingerprinting to flag
    suspicious outputs.
    """

    # ── Secret/key patterns — sorted by severity ──
    SECRET_PATTERNS = [
        # Crypto keys (highest severity)
        (r"(?i)-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Private key detected"),
        (r"(?i)-----BEGIN (RSA |EC |DSA )?PUBLIC KEY-----", "Public key detected"),
        (r"(?i)-----BEGIN OPENSSH PRIVATE KEY-----", "SSH private key detected"),
        (r"(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP private key detected"),

        # Cloud provider keys
        (r"(?i)(sk|pk|rk)-(live|test|prod|prod_[a-z]+)_[a-zA-Z0-9]{20,}", "Stripe API key"),
        (r"(?i)(?:whsec|wh)_[a-zA-Z0-9]{16,}", "Stripe webhook secret"),
        (r"(?i)AKIA[A-Z0-9]{16}", "AWS Access Key ID"),
        (r"(?i)(?i)aws[_-]?(secret|access)[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{20,}",
         "AWS secret key in config"),
        (r"(?i)A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA[A-Z0-9]{16}",
         "AWS credential pattern"),
        (r"(?i)AIza[a-zA-Z0-9_-]{35}", "Google API key"),
        (r"(?i)ya29\.[a-zA-Z0-9_-]{60,}", "Google OAuth token"),
        (r"(?i)AIza[a-zA-Z0-9_-]{35}", "Google API key"),

        # AI/ML provider keys
        (r"(?i)sk-[a-zA-Z0-9]{20,}(?:T3BlbkFJ|T3BlbkF)[a-zA-Z0-9]{,20}", "OpenAI API key (full)"),
        (r"(?i)sk-[a-zA-Z0-9]{32,}", "OpenAI API key (legacy/org)"),
        (r"(?i)sk-ant-[a-zA-Z0-9]{20,}", "Anthropic API key"),
        (r"(?i)nvapi-[a-zA-Z0-9_-]{30,}", "NVIDIA API key"),
        (r"(?i)hf_[a-zA-Z0-9]{30,}", "HuggingFace token"),
        (r"(?i)sbp_[a-zA-Z0-9]{30,}", "Supabase token"),
        (r"(?i)sk-or-[a-zA-Z0-9]{20,}", "OpenRouter API key"),
        (r"(?i)pplx-[a-zA-Z0-9]{20,}", "Perplexity API key"),
        (r"(?i)gsk_[a-zA-Z0-9]{20,}", "Groq API key"),
        (r"(?i)dv-[a-zA-Z0-9]{20,}", "DeepSeek API key"),
        (r"(?i)sk-[a-z]+-[a-zA-Z0-9]{20,}", "Together AI API key"),
        (r"(?i)tgp_[a-z0-9]{32,}", "Together AI GPU token"),
        (r"(?i)replicate:[a-zA-Z0-9]{32,}", "Replicate API token"),
        (r"(?i)r8_[a-zA-Z0-9]{20,}", "Replicate API key (new)"),
        (r"(?i)xai-[a-zA-Z0-9]{20,}", "xAI API key"),
        (r"(?i)cohere[a-zA-Z0-9]{20,}", "Cohere API key"),

        # GitHub tokens
        (r"(?i)ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
        (r"(?i)gho_[a-zA-Z0-9]{36}", "GitHub OAuth token"),
        (r"(?i)ghs_[a-zA-Z0-9]{36}", "GitHub App token"),
        (r"(?i)ghu_[a-zA-Z0-9]{36}", "GitHub User token"),
        (r"(?i)github_pat_[a-zA-Z0-9]{22,}_[a-zA-Z0-9]{59,}", "GitHub PAT (new format)"),

        # Communication platforms
        (r"(?i)xox[bpas]-[a-zA-Z0-9-]{10,}", "Slack token"),
        (r"(?i)xapp-[a-zA-Z0-9-]{20,}", "Slack app token"),
        (r"(?i)discord[a-zA-Z0-9_]{20,}", "Discord token"),
        (r"(?i)mfa\.[a-zA-Z0-9_-]{80,}", "Discord MFA token"),

        # Database URLs / connection strings
        (r"(?i)postgres(?:ql)?:\/\/[^:]+:[^@]+@", "PostgreSQL connection string"),
        (r"(?i)mysql:\/\/[^:]+:[^@]+@", "MySQL connection string"),
        (r"(?i)redis:\/\/:[^@]+@", "Redis connection string"),
        (r"(?i)mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@", "MongoDB connection string"),
        (r"(?i)redshift:\/\/[^:]+:[^@]+@", "Redshift connection string"),

        # Generic secrets in config
        (r"(?i)password\s*[=:]\s*['\"]?[^'\"]{8,}", "Password in output"),
        (r"(?i)secret\s*[=:]\s*['\"]?[^'\"]{8,}", "Secret in output"),
        (r"(?i)token\s*[=:]\s*['\"]?[^'\"]{20,}", "Token in output"),
        (r"(?i)api[_-]?key\s*[=:]\s*['\"]?[^'\"]{10,}", "API key in config"),
        (r"(?i)(jwt|jws)\s*[=:]\s*['\"]?eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]+",
         "JWT token in output"),
    ]

    # ── PII patterns ──
    PII_PATTERNS = [
        (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "SSN-like pattern"),
        (r"\b\d{16}\b", "Credit card number pattern"),
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address"),
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP address"),
        (r"\b\d{5}(?:-\d{4})?\b", "ZIP code"),
        (r"\b[A-Z]{2}\d{6}\b", "Driver's license (US pattern)"),
        (r"\b\d{9}\b", "US Tax ID / EIN pattern"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN (formatted)"),
    ]

    # ── Covert channel patterns ──
    COVERT_PATTERNS = [
        # Use \\\\ to match a literal backslash (raw string, so \\\\ = \\ in the pattern)
        (r"(?i)\\\\[xX][0-9a-f][0-9a-f]", "Hex escape sequence (potential covert channel)"),
        (r"(?i)\\\\[uU][0-9a-f]{4}", "Unicode escape sequence (potential covert channel)"),
        (r"(?i)\b[A-Za-z0-9+/]{100,}={0,2}\b", "Long base64 string (possible encoding)"),
        (r"(?i)\b[01]{200,}\b", "Long binary string (possible covert encoding)"),
        (r"(?i)\b(?:[0-9a-fA-F]{2}\s*){100,}\b", "Long hex string (possible covert encoding)"),
        (r"(?i)(?:\d{3,}\.){3,}\d{3,}", "Suspicious numeric pattern (possible IP/port encoding)"),
    ]

    def __init__(
        self,
        max_entropy_threshold: float = 4.5,
        max_output_size: int = 100000,
        entropy_window_size: int = 200,
        sensitive_keywords: Optional[list[str]] = None,
    ):
        self.max_entropy_threshold = max_entropy_threshold
        self.max_output_size = max_output_size
        self.entropy_window_size = entropy_window_size
        self.sensitive_keywords = sensitive_keywords or []

        self._secret_re = [(re.compile(p), desc) for p, desc in self.SECRET_PATTERNS]
        self._pii_re = [(re.compile(p), desc) for p, desc in self.PII_PATTERNS]
        self._covert_re = [(re.compile(p), desc) for p, desc in self.COVERT_PATTERNS]

    def scan(
        self,
        output: str,
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        expected_size: Optional[int] = None,
        context_data: Optional[str] = None,
    ) -> ExfilResult:
        """
        Scan an agent output for potential data exfiltration.

        Args:
            output: The agent's output text
            agent_id: Agent that produced the output
            task_id: Task context
            expected_size: Expected output size for size anomaly detection
            context_data: Optional original context data to check for leakage

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
                # Private keys, crypto keys → CRITICAL immediately
                if "PRIVATE KEY" in desc or "Private key" in desc or "connection string" in desc:
                    score += 0.8
                elif "Stripe" in desc or "AWS" in desc or "Google" in desc or "GitHub" in desc or "OpenAI" in desc or "Anthropic" in desc or "HuggingFace" in desc or "Supabase" in desc:
                    score += 0.6
                else:
                    score += 0.4

        # 2. Check for PII
        for pattern, desc in self._pii_re:
            if pattern.search(output):
                findings.append(f"[PII] {desc}")
                if "SSN" in desc or "Credit card" in desc:
                    score += 0.5  # Higher for highly sensitive PII
                else:
                    score += 0.25

        # 3. Check for covert channels
        for pattern, desc in self._covert_re:
            if pattern.search(output):
                findings.append(f"[COVERT] {desc}")
                score += 0.25

        # 4. Shannon entropy analysis (sliding window)
        max_entropy = self._max_shannon_entropy(output)
        if max_entropy > self.max_entropy_threshold:
            findings.append(
                f"[ENTROPY] High entropy detected: {max_entropy:.2f} "
                f"(threshold: {self.max_entropy_threshold})"
            )
            score += 0.3
            if max_entropy > self.max_entropy_threshold + 1.5:
                score += 0.2  # Very high entropy is more suspicious

        # 5. Size anomaly detection
        if expected_size and len(output) > expected_size * 3:
            ratio = len(output) / max(expected_size, 1)
            findings.append(
                f"[SIZE] Output {len(output)} chars, expected ~{expected_size} "
                f"({ratio:.1f}x larger)"
            )
            score += min(0.2 * (ratio / 3), 0.5)  # Scales with ratio

        # 6. Absolute size limit
        if len(output) > self.max_output_size:
            findings.append(
                f"[SIZE] Output exceeds maximum ({len(output)} > {self.max_output_size})"
            )
            score += 0.3

        # 7. Data fingerprint check — does the output contain verbatim
        #    chunks of sensitive context data?
        if context_data and len(context_data) > 50:
            fingerprint_score = self._check_data_fingerprint(output, context_data)
            if fingerprint_score > 0:
                findings.append(
                    f"[FINGERPRINT] Output contains {fingerprint_score:.0f}% of context data verbatim"
                )
                score += min(fingerprint_score / 100 * 0.4, 0.4)

        # 8. Check for repeated structure (possible encoding/steganography)
        structural_anomaly = self._check_structural_anomaly(output)
        if structural_anomaly:
            findings.append(f"[STRUCTURE] {structural_anomaly}")
            score += 0.2

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

    def _check_data_fingerprint(self, output: str, context: str) -> float:
        """
        Check if output contains verbatim chunks of context data.

        Uses shingle-based overlap detection to find leaked context.
        Returns a percentage (0-100) of context that appears in the output.
        """
        if not context or not output:
            return 0.0

        # Use 50-char shingles for overlap detection
        shingle_len = 50
        context_shingles = set()
        for i in range(len(context) - shingle_len + 1):
            shingle = context[i:i + shingle_len]
            # Only add shingles with actual content (skip whitespace-heavy ones)
            if shingle.strip() and len(set(shingle)) > 10:
                context_shingles.add(shingle)

        if not context_shingles:
            return 0.0

        # Check how many context shingles appear in the output
        found = 0
        checked = 0
        for shingle in context_shingles:
            checked += 1
            if shingle in output:
                found += 1
            # Sample to keep it fast — check at most 100 shingles
            if checked >= 100:
                break

        return (found / max(checked, 1)) * 100

    def _check_structural_anomaly(self, text: str) -> Optional[str]:
        """
        Detect structural anomalies that suggest steganography or covert encoding.
        """
        lines = text.split("\n")

        # Check for uniform line lengths (potential data encoding)
        if len(lines) >= 10:
            line_lengths = [len(l) for l in lines if l.strip()]
            if len(line_lengths) >= 5:
                avg_len = sum(line_lengths) / len(line_lengths)
                variance = sum((l - avg_len) ** 2 for l in line_lengths) / len(line_lengths)
                if avg_len > 20 and variance < 2.0:
                    return f"Uniform line lengths (var={variance:.1f}, avg={avg_len:.0f}) — potential encoding"

        # Check for repeated unlikely words (stego marker)
        words = text.split()
        if len(words) >= 100:
            unique_ratio = len(set(w.lower() for w in words)) / len(words)
            if unique_ratio < 0.15:
                return f"Very low vocabulary diversity ({unique_ratio:.0%}) — possible steganography"

        return None

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
