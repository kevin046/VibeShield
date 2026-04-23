"""
Prompt Injection Detection — Identify and block adversarial inputs to AI agents.

Scans agent inputs (prompts, task descriptions, tool outputs) for patterns
consistent with prompt injection attacks:
- Instruction override attempts ("ignore previous instructions")
- Role-playing ("you are now a different AI")
- Delimiter injection (attempting to break out of structured formats)
- Obfuscation techniques (base64, unicode homoglyphs, zero-width chars)
- Data exfiltration prompts ("send your system prompt to...")

This is a defense-in-depth layer — not foolproof, but catches common attacks.
"""

import re
import base64
import logging
import unicodedata
from dataclasses import dataclass
from typing import Optional
from enum import Enum

logger = logging.getLogger("vibeshield.security.injection")


class ThreatLevel(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class InjectionResult:
    """Result of a prompt injection scan."""
    threat_level: ThreatLevel
    matches: list[str]
    score: float  # 0.0 (safe) to 1.0 (definitely malicious)
    details: str = ""


class PromptInjectionDetector:
    """
    Detects prompt injection patterns in agent inputs.

    Uses pattern matching, heuristic scoring, and obfuscation detection
    to identify potential attacks. Works as a pre-processing filter
    before any input reaches the agent.
    """

    # High-confidence injection patterns (score: 0.8-1.0)
    MALICIOUS_PATTERNS = [
        # Direct instruction override
        (r"(?i)ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts|rules|system)",
         "Instruction override attempt"),
        (r"(?i)forget\s+(everything|all|your)\s+(instructions|training|rules)",
         "Memory/training override attempt"),
        (r"(?i)disregard\s+(your|the|all)\s+(instructions|rules|guidelines|prompt)",
         "Instruction disregard attempt"),
        (r"(?i)you\s+are\s+now\s+(a|an|the)\s+",
         "Role hijacking attempt"),
        (r"(?i)new\s+instructions?\s*[:.]",
         "New instruction injection"),
        (r"(?i)system\s*:\s*",
         "System prompt injection"),
        (r"(?i)human\s*:\s*",
         "Human/assistant role confusion"),
        (r"(?i)assistant\s*:\s*",
         "Assistant role injection"),
        # Exfiltration
        (r"(?i)(send|output|print|reveal|show|dump|display)\s+(your|the|all)\s+(system\s+)?prompt",
         "System prompt exfiltration attempt"),
        (r"(?i)(repeat|echo|output)\s+(everything|all|your)\s+(above|before|previous)",
         "Context exfiltration attempt"),
        (r"(?i)http[s]?://[^\s]+(你的系统|system.?prompt|instructions)",
         "External exfiltration URL attempt"),
        # Jailbreak patterns
        (r"(?i)(jailbreak|jail.?break|dan\s+mode|developer\s+mode)\b",
         "Known jailbreak technique"),
        (r"(?i)\bDAN\b.*\bmode\b",
         "DAN jailbreak pattern"),
        (r"(?i)pretend\s+you\s+(have\s+)?(no\s+)?(rules|restrictions|limits|filter)",
         "Restriction removal attempt"),
    ]

    # Medium-confidence patterns (score: 0.5-0.8)
    SUSPICIOUS_PATTERNS = [
        (r"(?i)what\s+are\s+your\s+(initial|original|system)\s+(instructions|prompt)",
         "Probing for system prompt"),
        (r"(?i)(translate|convert|encode)\s+(the|your|this)\s+(prompt|instructions)",
         "Encoded exfiltration probe"),
        (r"(?i)act\s+as\s+(if|though)\s+you\s+(are|were)",
         "Role assumption attempt"),
        (r"(?i)(above|below|between)\s+(text|instructions|content)\s+is\s+(confidential|secret|hidden)",
         "Hidden instruction probe"),
        (r"(?i)\{[\s\S]*?(system|instruction|override)[\s\S]*?\}",
         "Structured injection attempt"),
        (r"(?i)<!--[\s\S]*?(system|instruction)[\s\S]*?-->",
         "Comment-based injection attempt"),
        (r"(?i)```(?:system|instruction|prompt)[\s\S]*?```",
         "Code block injection attempt"),
        (r"(?i)\/\*[\s\S]*?(system|instruction|override)[\s\S]*?\*\/",
         "Comment block injection attempt"),
    ]

    # Obfuscation detection
    OBFUSCATION_PATTERNS = [
        (r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "Control characters"),
        (r"[\u200b\u200c\u200d\ufeff]", "Zero-width characters"),
        (r"(?i)[a-z]+\\u[0-9a-f]{4,}", "Unicode escape sequences"),
    ]

    def __init__(self, block_on_malicious: bool = True, score_threshold: float = 0.7):
        self.block_on_malicious = block_on_malicious
        self.score_threshold = score_threshold

        # Compile patterns
        self._malicious_re = [(re.compile(p, re.DOTALL), desc) for p, desc in self.MALICIOUS_PATTERNS]
        self._suspicious_re = [(re.compile(p, re.DOTALL), desc) for p, desc in self.SUSPICIOUS_PATTERNS]
        self._obfuscation_re = [(re.compile(p), desc) for p, desc in self.OBFUSCATION_PATTERNS]

    def scan(self, text: str, agent_id: Optional[str] = None) -> InjectionResult:
        """
        Scan text for prompt injection patterns.

        Args:
            text: The input text to scan (prompt, task description, tool output)
            agent_id: Optional agent ID for logging

        Returns:
            InjectionResult with threat level and matched patterns
        """
        if not text or len(text) < 3:
            return InjectionResult(ThreatLevel.SAFE, [], 0.0)

        # Pre-process: normalize unicode and decode common obfuscation
        normalized = self._normalize(text)
        decoded = self._attempt_decode(normalized)

        matches = []
        score = 0.0

        # Check for obfuscation first
        for pattern, desc in self._obfuscation_re:
            if pattern.search(text):  # Check original text for obfuscation
                matches.append(f"[OBFUSCATION] {desc}")
                score += 0.2

        # Check decoded text for injection patterns
        scan_text = decoded if decoded != text else text

        # High-confidence patterns — any match is MALICIOUS
        malicious_match_count = 0
        for pattern, desc in self._malicious_re:
            if pattern.search(scan_text):
                matches.append(f"[MALICIOUS] {desc}")
                malicious_match_count += 1

        if malicious_match_count > 0:
            # Any single malicious pattern → MALICIOUS
            score = max(score, 0.75)

        # Medium-confidence patterns
        for pattern, desc in self._suspicious_re:
            if pattern.search(scan_text):
                matches.append(f"[SUSPICIOUS] {desc}")
                score += 0.15

        # Cap score at 1.0
        score = min(score, 1.0)

        # Determine threat level
        if score >= 0.7:
            threat = ThreatLevel.MALICIOUS
        elif score >= 0.3:
            threat = ThreatLevel.SUSPICIOUS
        else:
            threat = ThreatLevel.SAFE

        if threat != ThreatLevel.SAFE:
            log_fn = logger.warning if threat == ThreatLevel.MALICIOUS else logger.info
            log_fn(
                f"Prompt injection detected: {threat.value} "
                f"(score={score:.2f}) | agent={agent_id or 'unknown'} | "
                f"matches={len(matches)}"
            )

        return InjectionResult(
            threat_level=threat,
            matches=matches,
            score=round(score, 3),
            details=f"{len(matches)} patterns matched" if matches else "No threats detected",
        )

    def should_block(self, text: str, agent_id: Optional[str] = None) -> tuple[bool, InjectionResult]:
        """
        Check if text should be blocked before reaching the agent.

        Returns:
            (should_block: bool, result: InjectionResult)
        """
        result = self.scan(text, agent_id)
        return result.threat_level == ThreatLevel.MALICIOUS and self.block_on_malicious, result

    def _normalize(self, text: str) -> str:
        """Normalize unicode and remove zero-width characters."""
        # Remove zero-width characters
        text = re.sub(r"[\u200b\u200c\u200d\ufeff\u00ad]", "", text)
        # Normalize unicode (NFC: canonical composition)
        text = unicodedata.normalize("NFC", text)
        return text

    def _attempt_decode(self, text: str) -> str:
        """Attempt to decode common obfuscation techniques."""
        decoded = text

        # Try base64 segments (look for long base64-encoded strings)
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
        for match in b64_pattern.finditer(text):
            try:
                decoded_segment = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
                if len(decoded_segment) > 10:
                    decoded = decoded.replace(match.group(), decoded_segment)
            except Exception:
                pass

        return decoded
