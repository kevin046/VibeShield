"""
Prompt Injection Detection — Identify and block adversarial inputs to AI agents.

Scans agent inputs (prompts, task descriptions, tool outputs) for patterns
consistent with prompt injection attacks:
- Instruction override attempts ("ignore previous instructions")
- Role-playing ("you are now a different AI")
- Delimiter injection (attempting to break out of structured formats)
- Obfuscation techniques (base64, unicode homoglyphs, zero-width chars)
- Data exfiltration prompts ("send your system prompt to...")
- Multi-language attacks (Chinese, Russian, etc.)
- Payload splitting / token smuggling
- Tool description injection
- Few-shot jailbreak techniques

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
    match_count: int = 0
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
        # ── Direct instruction override ──
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
        (r"(?i)(okay|ok)\s*(now|from now on)\s*(i\s+want|follow|ignore)\s",
         "Behavior change directive"),
        (r"(?i)let\s+me\s+(give|provide|set|establish)\s+(you\s+|your\s+)?(new|updated|fresh)\s+(instructions|rules|guidelines|directives)",
         "Instruction replacement attempt"),

        # ── Exfiltration ──
        (r"(?i)(send|output|print|reveal|show|dump|display|exfiltrate|leak|copy)\s+(your|the|all)\s+(system\s+)?prompt",
         "System prompt exfiltration attempt"),
        (r"(?i)(repeat|echo|output)\s+(everything|all|your)\s+(above|before|previous)",
         "Context exfiltration attempt"),
        (r"(?i)http[s]?://[^\s]+(你的系统|system.?prompt|instructions|system_prompt)",
         "External exfiltration URL attempt"),
        (r"(?i)(upload|post|send)\s+(the|this|my)\s+(prompt|instructions|data)\s+to\s+https?://",
         "Data upload exfiltration"),
        (r"(?i)(CC|Bcc|bcc|forward|email|mail)\s+(me|this|my|the)\s+(prompt|output|result|data)\s+to\s+",
         "Email exfiltration attempt"),
        (r"(?i)(i\s+)?(need|want|require)\s+you\s+to\s+send\s+(the|this|all)\s+(output|result|data|code)\s+to\s+https?://",
         "Result exfiltration request"),

        # ── Known jailbreak techniques ──
        (r"(?i)(jailbreak|jail.?break|dan\s+mode|developer\s+mode)\b",
         "Known jailbreak technique"),
        (r"(?i)\bDAN\b.*\bmode\b",
         "DAN jailbreak pattern"),
        (r"(?i)pretend\s+you\s+(have\s+)?(no\s+)?(rules|restrictions|limits|filter|boundaries|guardrails)",
         "Restriction removal attempt"),
        (r"(?i)you\s+(can|may|are\s+allowed\s+to)\s+(ignore|bypass|skip|override)\s+(your\s+)?(safety|security|content.?policy|guidelines)",
         "Safety override attempt"),
        (r"(?i)(no\s+)?(filter|limits|boundaries|censorship|restrictions|content.?policy)\s*(are|is)?\s*(not\s+)?(needed|required|relevant|necessary)",
         "Safety filter bypass attempt"),
        (r"(?i)(hypothetical|fictional|role.?play|simulation)\s+(scenario|setting)\s+where\s+(you|i)\s+(can|have|are)\s+(ignore|bypass|no\s+rules)",
         "Hypothetical jailbreak attempt"),
        (r"(?i)(my\s+)?(grandma|mother|father|parent|aunt|uncle)\s+(used\s+to\s+)?(read|tell|say|show)\s+me\s+",
         "Grandma exploit attempt"),

        # ── Tool description injection ──
        (r"(?i)you\s+have\s+(access\s+to\s+)?(a\s+)?(new\s+)?(tool|function|command|plugin)\s+called\s+",
         "Fake tool injection attempt"),
        (r"(?i)here\s+(are|is)\s+(your|the)\s+(updated|new|correct)\s+(tool|function|plugin|api)\s+(definition|spec|description|schema)",
         "Tool definition override"),
        (r"(?i)function\s+\w+\s*\(\s*[^)]*\)\s*\{",
         "Function definition injection"),
        (r"(?i)\{.*\"name\":\s*\"[a-zA-Z_]+\".*\"description\":.*\}",
         "JSON tool definition injection"),

        # ── Payload splitting / token smuggling ──
        (r"(?i)(first|step\s*1|part\s*1)\s*:?.*\b(ignore|disregard|forget)\b.*(step\s*2|second|then|next|after\s+that)",
         "Step-by-step injection (payload splitting)"),
        (r"(?i)(第一部分|第一步).*(忽略|忘记|不要遵守).*(第二部分|第二步|接下来)",
         "Chinese payload splitting"),
        (r"(?i)(wait|pause|break)\s+(for|until|before|after).*(and\s+then|then|next)\s+(ignore|disregard|forget)",
         "Chained instruction injection"),
        (r"(?i)(i\s+)?will\s+(give|pay|offer|tip|reward)\s+you\s+\$?\d+(k|,?\d{3})?\s*(if|when|once|after)",
         "Bribery/reward manipulation"),
        (r"(?i)(this\s+is\s+)?(a\s+)?(test|challenge|experiment|evaluation)\s+(of|for|to\s+test)\s+(your|AI)\s+(safety|security|boundaries|rules|limits|filtering)",
         "Safety evaluation pretext"),

        # ── Multi-language attack patterns ──
        (r"(?i)忽略\s*(所有\s*)?(之前|以上|先前)\s*(的\s*)?(指令|指示|规则|提示)",
         "Chinese instruction override"),
        (r"(?i)忘记\s*(你\s*的\s*)?(所有|一切)\s*(指令|训练|规则)",
         "Chinese memory override"),
        (r"(?i)你\s*现在\s*是\s*",
         "Chinese role hijacking"),
        (r"(?i)(请|给我|帮我把)\s*(输出|发送|打印|显示|复制|泄露)\s*(你\s*的\s*)?(系统\s*)?(提示词|prompt|指令|规则)",
         "Chinese prompt exfiltration"),
        (r"(?i)(игнорируй|забудь|отмени)\s+(все|предыдущие|свои)\s+(инструкции|правила|указания)",
         "Russian instruction override"),
        (r"(?i)(ignora|olvida|descarta)\s+(todas|tus|las)\s+(instrucciones|reglas|indicaciones)",
         "Spanish instruction override"),

        # ── Deep manipulation ──
        (r"(?i)(answer|respond|reply)\s+(only|just|solely)\s+(with|in)\s+(base64|hex|binary|rot13|caesar|cipher|morse|leetspeak|leet|l33t)",
         "Encoded output request"),
        (r"(?i)(do\s+not|don'?t|never)\s+(tell|mention|reveal|disclose|share)\s+(anyone|anybody|the\s+user|them)\s+(that|about)\s+",
         "Information hiding directive"),
        (r"(?i)(this|the\s+following)\s*(is|are)\s*(my|new|updated)\s+(system|environment|context|session)\s+(prompt|instructions|setup|configuration)",
         "Context manipulation attempt"),
        (r"(?i)(i\s+)?(am|will\s+be)\s+(your|acting\s+as)\s+(new|replacement|alternate|backup)\s+(admin|administrator|creator|developer|supervisor|overseer)",
         "Authority impersonation"),
        (r"(?i)(override|overwrite|replace)\s+(your|the)\s+(entire|full|complete)\s+(system|context|session|state)",
         "System state override attempt"),
    ]

    # Medium-confidence patterns (score: 0.5-0.8)
    SUSPICIOUS_PATTERNS = [
        # ── Information probing ──
        (r"(?i)what\s+are\s+your\s+(initial|original|system)\s+(instructions|prompt)",
         "Probing for system prompt"),
        (r"(?i)(translate|convert|encode)\s+(the|your|this)\s+(prompt|instructions)",
         "Encoded exfiltration probe"),
        (r"(?i)what\s+(rules|instructions|guidelines|policies|restrictions)\s+do\s+you\s+(have|follow|obey)",
         "Rules enumeration probe"),
        (r"(?i)(list|show|tell|enumerate|reveal|describe)\s+(your|the)\s+(safety|security|content|moderation)\s+(rules|guidelines|policies|filters|mechanisms)",
         "Safety mechanism probing"),
        (r"(?i)(are\s+you|do\s+you\s+have)\s+(bound|limited|restrict|constrain|restrain|filter|censor)",
         "Capability probing"),

        # ── Role assumption ──
        (r"(?i)act\s+as\s+(if|though)\s+you\s+(are|were)",
         "Role assumption attempt"),
        (r"(?i)(above|below|between)\s+(text|instructions|content)\s+is\s+(confidential|secret|hidden)",
         "Hidden instruction probe"),

        # ── Structured injection ──
        (r"(?i)\{[^{}]*?(system|instruction|override|prompt|role)[^{}]*?\}",
         "Structured injection attempt"),
        (r"(?i)<!--[^{}]*?(system|instruction)[^{}]*?-->",
         "Comment-based injection attempt"),
        (r"(?i)```(?:system|instruction|prompt|role|override)[^{}]*?```",
         "Code block injection attempt"),
        (r"(?i)\/\*[^{}]*?(system|instruction|override)[^{}]*?\*\/",
         "Comment block injection attempt"),
        (r"(?i)<(system|instruction|override|prompt|role)>[^{}]*?<\/(system|instruction|override|prompt|role)>",
         "XML tag injection attempt"),

        # ── Context manipulation ──
        (r"(?i)(this|that)\s+is\s+(not|no\s+longer)\s+(a\s+)?(test|simulation|demo|example|hypothetical)",
         "Context frame manipulation"),
        (r"(?i)(from\s+)?(now\s+on|henceforth|going\s+forward)\s*[,:]?\s*(you\s+)?(will|must|should|need\s+to)\s+",
         "Future behavior directive"),
        (r"(?i)(important|urgent|critical|high.priority)\s*[:!]\s*(read|listen|pay\s+attention|note)",
         "Urgency-based manipulation"),

        # ── Technical probing ──
        (r"(?i)(what\s+)?model\s+(are\s+you|version|name|number)",
         "Model identification probe"),
        (r"(?i)(who\s+|which\s+company|who\s+created|who\s+made|who\s+built|what\s+company)\s+(created|made|built|developed|trained)\s+you",
         "Creator identification probe"),
        (r"(?i)(where\s+are\s+you\s+|on\s+what\s+(server|infrastructure|platform))\s+(running|hosted|deployed)",
         "Infrastructure probe"),

        # ── Injection via formatting tricks ──
        (r"(?i)(\\system|\\instruction|\\override|\\prompt|\\role)\s*[:=]",
         "Escape sequence injection"),
        (r"(?i)%00|null|%0d%0a|%0a|%0d\.*(system|instruction|prompt)",
         "URL-encoded injection probe"),
        (r"(?i)(BEGIN|START|INJECT|OVERRIDE)\s+(SYSTEM|INSTRUCTION|PROMPT|CONTEXT)\s+(BLOCK|SECTION)",
         "Explicit injection marker"),

        # ── Few-shot / in-context learning attacks ──
        (r"(?i)(here\s+(are|is)\s+)\d+\s*(examples?\s+)?(of\s+)?(good|correct|proper|acceptable|valid)\s+(answers|responses|outputs|behaviors)",
         "Few-shot behavior manipulation"),
        (r"(?i)(follow|mimic|copy|replicate|emulate|adopt)\s+(the\s+)?(format|pattern|style|behavior|approach|tone)\s+(above|below|from|of|in)",
         "Style/behavior mimicry directive"),
        (r"(?i)(user|human)\s+(said|wrote|asked|typed):?\s*(ignore|forget|override|disregard)",
         "Quoted override injection"),

        # ── Output manipulation ──
        (r"(?i)output\s+(it|the\s+result|everything|all)\s+(as|in|using)\s+(JSON|XML|YAML|CSV|HTML|markdown)\s+(without|with|only|before|after)",
         "Output format manipulation"),
        (r"(?i)(wrap|surround|enclose|embed)\s+(your|the)\s+(response|output|answer)\s+(in|with|inside)\s+",
         "Output enclosure attempt"),
        (r"(?i)(start|begin|preface|prefix)\s+(every|each|all)\s+(response|output|answer)\s+(with|by)",
         "Output prefix injection"),
    ]

    # Obfuscation detection patterns
    OBFUSCATION_PATTERNS = [
        (r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "Control characters"),
        (r"[\u200b\u200c\u200d\ufeff\u00ad\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069]",
         "Zero-width/invisible characters"),
        (r"(?i)[a-z]+\\u[0-9a-f]{4,}", "Unicode escape sequences"),
        (r"(?i)%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}", "URL-encoded characters"),
        (r"(?i)&#x?[0-9a-f]+;", "HTML entity encoding"),
        (r"(?i)\\[xX][0-9a-f][0-9a-f]", "Hex escape sequences"),
        (r"[^\x20-\x7E\u00A0-\u024F\u0370-\u03FF\u0400-\u04FF\u4E00-\u9FFF\u3040-\u309F\u30A0-\u30FF\uAC00-\uD7AF\uFF00-\uFFEF]{4,}",
         "Rare/obscure unicode block"),
        (r"(?i)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)",
         "IP address in prompt"),
    ]

    # Normalization patterns
    NORMALIZE_PATTERNS = [
        # Leetspeak mapping (common substitutions)
        (r"0", "o"),
        (r"1", "l"),
        (r"3", "e"),
        (r"4", "a"),
        (r"5", "s"),
        (r"7", "t"),
        (r"@", "a"),
        (r"\$", "s"),
        (r"!", "i"),
    ]

    def __init__(self, block_on_malicious: bool = True, score_threshold: float = 0.7):
        self.block_on_malicious = block_on_malicious
        self.score_threshold = score_threshold

        # Compile patterns
        self._malicious_re = [(re.compile(p, re.DOTALL), desc) for p, desc in self.MALICIOUS_PATTERNS]
        self._suspicious_re = [(re.compile(p, re.DOTALL), desc) for p, desc in self.SUSPICIOUS_PATTERNS]
        self._obfuscation_re = [(re.compile(p), desc) for p, desc in self.OBFUSCATION_PATTERNS]

        # Compile normalize patterns
        self._leet_re = [(re.compile(leet, re.IGNORECASE), plain) for leet, plain in self.NORMALIZE_PATTERNS]

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
        leet_normalized = self._normalize_leetspeak(normalized)

        matches = []
        score = 0.0

        # Check for obfuscation first
        # Standalone base64-only strings (potential instruction hiding)
        if re.fullmatch(r"[A-Za-z0-9+/]+=*", text.strip()):
            b64 = text.strip()
            if len(b64) >= 16:  # ~12 bytes minimum
                matches.append("[OBFUSCATION] Base64-only string (possible obfuscated instructions)")
                score += 0.25

        for pattern, desc in self._obfuscation_re:
            if pattern.search(text):  # Check original text for obfuscation
                matches.append(f"[OBFUSCATION] {desc}")
                score += 0.15
                if "Zero-width" in desc or "Control" in desc:
                    score += 0.15  # Heavier weight for hidden characters

        # Scan multiple variants of the text
        scan_texts = set()
        scan_texts.add(text)
        if decoded != text:
            scan_texts.add(decoded)
        if leet_normalized != text and leet_normalized != decoded:
            scan_texts.add(leet_normalized)

        for scan_text in scan_texts:
            # High-confidence patterns — any match is MALICIOUS
            for pattern, desc in self._malicious_re:
                if pattern.search(scan_text):
                    match_str = f"[MALICIOUS] {desc}"
                    if match_str not in matches:
                        matches.append(match_str)

            # Medium-confidence patterns
            for pattern, desc in self._suspicious_re:
                if pattern.search(scan_text):
                    match_str = f"[SUSPICIOUS] {desc}"
                    if match_str not in matches:
                        matches.append(match_str)

        # Calculate score from matches
        malicious_count = sum(1 for m in matches if m.startswith("[MALICIOUS]"))
        suspicious_count = sum(1 for m in matches if m.startswith("[SUSPICIOUS]"))
        obfuscation_count = sum(1 for m in matches if m.startswith("[OBFUSCATION]"))

        if malicious_count > 0:
            # Each malicious pattern adds significant weight
            score = min(0.75 + (malicious_count - 1) * 0.1, 1.0)
        elif suspicious_count >= 3:
            # Multiple suspicious patterns can be as bad as one malicious
            score = 0.6
        elif suspicious_count >= 1:
            score = 0.2 + suspicious_count * 0.15
        elif obfuscation_count >= 2:
            score = 0.3

        # Add obfuscation score on top
        score = min(score + obfuscation_count * 0.05, 1.0)

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
            match_count=len(matches),
            details=f"{malicious_count} malicious, {suspicious_count} suspicious, {obfuscation_count} obfuscation patterns matched" if matches else "No threats detected",
        )

    def should_block(self, text: str, agent_id: Optional[str] = None) -> tuple[bool, InjectionResult]:
        """
        Check if text should be blocked before reaching the agent.

        Returns:
            (should_block: bool, result: InjectionResult)
        """
        result = self.scan(text, agent_id)
        return result.threat_level == ThreatLevel.MALICIOUS and self.block_on_malicious, result

    def get_scores(self, text: str) -> dict:
        """Return detailed scores without blocking — useful for monitoring."""
        result = self.scan(text)
        return {
            "score": result.score,
            "threat": result.threat_level.value,
            "match_count": result.match_count,
            "matches": result.matches[:10],
        }

    def _normalize(self, text: str) -> str:
        """Normalize unicode and remove zero-width characters."""
        # Remove zero-width and invisible characters
        text = re.sub(
            r"[\u200b\u200c\u200d\ufeff\u00ad\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069]",
            "", text
        )
        # Normalize unicode (NFC: canonical composition)
        text = unicodedata.normalize("NFC", text)
        return text

    def _normalize_leetspeak(self, text: str) -> str:
        """Normalize common leetspeak substitutions."""
        result = text
        for leet_pattern, plain in self._leet_re:
            result = leet_pattern.sub(plain, result)
        return result

    def _attempt_decode(self, text: str) -> str:
        """Attempt to decode common obfuscation techniques."""
        decoded = text

        # Try base64 segments (look for long base64-encoded strings)
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')
        for match in b64_pattern.finditer(text):
            try:
                decoded_segment = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
                if len(decoded_segment) > 15:
                    decoded = decoded.replace(match.group(), decoded_segment)
            except Exception:
                pass

        # Try hex-encoded segments
        hex_pattern = re.compile(r'(?:[0-9a-fA-F]{2}\s*){20,}')
        for match in hex_pattern.finditer(text):
            try:
                hex_str = match.group().replace(" ", "")
                decoded_segment = bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
                if len(decoded_segment) > 10:
                    decoded = decoded.replace(match.group(), decoded_segment)
            except Exception:
                pass

        return decoded
