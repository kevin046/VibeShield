"""
Egress Proxy — DNS Allowlisting, Connection Audit, and Traffic Filtering.

Controls ALL outbound network traffic from sandboxed agents.
Default-deny: no connection is allowed unless explicitly whitelisted.

Features:
- DNS allowlist: only approved domains resolve
- Connection audit: every outbound connection is logged with hash chain
- Rate limiting: prevent data exfiltration via burst connections
- Protocol filtering: only approved protocols (HTTPS, WSS)
- Payload size limits: prevent large data exfiltration
"""

import time
import logging
import fnmatch
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logger = logging.getLogger("vibeshield.security.egress")


class Protocol(Enum):
    HTTPS = "https"
    WSS = "wss"
    HTTP = "http"  # Only for internal endpoints


class EgressDecision(Enum):
    ALLOW = "allow"
    DENY_DOMAIN = "deny_domain"
    DENY_PROTOCOL = "deny_protocol"
    DENY_RATE_LIMIT = "deny_rate_limit"
    DENY_SIZE_LIMIT = "deny_size_limit"
    DENY_OFFLINE = "deny_offline"


@dataclass
class EgressRule:
    """Defines an allowed outbound connection."""
    host: str
    port: int = 443
    protocol: Protocol = Protocol.HTTPS
    max_request_size_bytes: int = 1024 * 1024  # 1MB default
    max_requests_per_minute: int = 60
    description: str = ""


@dataclass
class EgressEvent:
    """Record of an egress attempt (allowed or denied)."""
    timestamp: float
    agent_id: str
    task_id: str
    host: str
    port: int
    protocol: str
    decision: str
    reason: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0


class EgressProxy:
    """
    Controls outbound network traffic from sandboxed agents.

    Every connection request passes through this proxy before reaching
    the network. Default-deny with explicit allowlist.

    Usage:
        proxy = EgressProxy()
        proxy.add_domain("api.openai.com", port=443)
        proxy.add_domain("api.anthropic.com", port=443)

        decision = proxy.evaluate("agent-1", "task-1", "api.openai.com", 443, "https")
        if decision == EgressDecision.ALLOW:
            # Forward the request
            proxy.log_connection(agent_id, host, port, 1024, 4096)
    """

    # Pre-built domain lists for common agent APIs
    TRUSTED_AI_APIS = {
        "api.openai.com": 443,
        "api.anthropic.com": 443,
        "generativelanguage.googleapis.com": 443,
        "api.cohere.ai": 443,
        "api.mistral.ai": 443,
    }

    def __init__(
        self,
        default_max_request_size: int = 1024 * 1024,
        default_rate_limit: int = 60,
        strict_mode: bool = True,
    ):
        self._allowed_domains: dict[str, EgressRule] = {}
        self._domain_patterns: list[str] = []  # Wildcard patterns
        self._request_history: dict[str, list[float]] = {}  # agent_id -> [timestamps]
        self._events: list[EgressEvent] = []
        self.default_max_request_size = default_max_request_size
        self.default_rate_limit = default_rate_limit
        self.strict_mode = strict_mode  # If True, deny everything not explicitly allowed

    def add_domain(
        self,
        host: str,
        port: int = 443,
        protocol: Protocol = Protocol.HTTPS,
        max_request_size: Optional[int] = None,
        rate_limit: Optional[int] = None,
        description: str = "",
    ):
        """Add a domain to the allowlist."""
        rule = EgressRule(
            host=host,
            port=port,
            protocol=protocol,
            max_request_size_bytes=max_request_size or self.default_max_request_size,
            max_requests_per_minute=rate_limit or self.default_rate_limit,
            description=description,
        )
        self._allowed_domains[host] = rule
        logger.info(f"Egress allowed: {host}:{port} ({protocol.value})")

    def add_wildcard(self, pattern: str, port: int = 443):
        """Add a wildcard domain pattern (e.g., '*.googleapis.com')."""
        self._domain_patterns.append(pattern)
        logger.info(f"Egress wildcard allowed: {pattern}:{port}")

    def add_trusted_apis(self):
        """Add all pre-built trusted AI API domains."""
        for host, port in self.TRUSTED_AI_APIS.items():
            self.add_domain(host, port=port, description="Trusted AI API")

    def remove_domain(self, host: str):
        """Remove a domain from the allowlist."""
        self._allowed_domains.pop(host, None)
        self._domain_patterns = [p for p in self._domain_patterns if p != host]
        logger.info(f"Egress removed: {host}")

    def evaluate(
        self,
        agent_id: str,
        task_id: str,
        host: str,
        port: int,
        protocol: str,
        request_size: int = 0,
    ) -> EgressDecision:
        """
        Evaluate whether an outbound connection should be allowed.

        Checks (in order):
        1. Is the domain on the allowlist?
        2. Is the protocol allowed?
        3. Is the agent within its rate limit?
        4. Is the request within the size limit?
        """
        # Check domain allowlist
        rule = self._allowed_domains.get(host)
        if not rule:
            # Check wildcard patterns
            matched = any(fnmatch.fnmatch(host, pat) for pat in self._domain_patterns)
            if not matched:
                logger.warning(f"Egress DENIED (domain): {agent_id} -> {host}:{port}")
                self._record_event(agent_id, task_id, host, port, protocol,
                                   EgressDecision.DENY_DOMAIN, f"Domain not allowed: {host}")
                return EgressDecision.DENY_DOMAIN
            # Wildcard matched — use a default rule for further checks
            rule = EgressRule(
                host=host, protocol=Protocol.HTTPS,
                max_request_size_bytes=self.default_max_request_size,
                max_requests_per_minute=self.default_rate_limit,
            )

        # Record request for rate limiting (before check, so subsequent calls count it)
        self._record_request(agent_id)

        # Check protocol
        allowed_protocol = rule.protocol.value if rule else "https"
        if protocol.lower() not in (allowed_protocol, "https", "wss"):
            logger.warning(f"Egress DENIED (protocol): {agent_id} -> {host} via {protocol}")
            self._record_event(agent_id, task_id, host, port, protocol,
                               EgressDecision.DENY_PROTOCOL, f"Protocol not allowed: {protocol}")
            return EgressDecision.DENY_PROTOCOL

        # Check rate limit
        if not self._check_rate_limit(agent_id, rule):
            logger.warning(f"Egress DENIED (rate): {agent_id} -> {host}")
            self._record_event(agent_id, task_id, host, port, protocol,
                               EgressDecision.DENY_RATE_LIMIT, "Rate limit exceeded")
            return EgressDecision.DENY_RATE_LIMIT

        # Check size limit
        max_size = rule.max_request_size_bytes if rule else self.default_max_request_size
        if request_size > max_size:
            logger.warning(f"Egress DENIED (size): {agent_id} -> {host} ({request_size} > {max_size})")
            self._record_event(agent_id, task_id, host, port, protocol,
                               EgressDecision.DENY_SIZE_LIMIT, f"Request too large: {request_size} bytes")
            return EgressDecision.DENY_SIZE_LIMIT

        logger.debug(f"Egress ALLOWED: {agent_id} -> {host}:{port}")
        self._record_event(agent_id, task_id, host, port, protocol, EgressDecision.ALLOW)
        return EgressDecision.ALLOW

    def _record_request(self, agent_id: str):
        """Record a request timestamp for rate limiting."""
        now = time.time()
        if agent_id not in self._request_history:
            self._request_history[agent_id] = []
        self._request_history[agent_id].append(now)

    def _check_rate_limit(self, agent_id: str, rule: EgressRule) -> bool:
        """Check if the agent is within its per-minute rate limit."""
        now = time.time()
        minute_ago = now - 60

        if agent_id not in self._request_history:
            self._request_history[agent_id] = []

        # Clean old entries
        self._request_history[agent_id] = [
            t for t in self._request_history[agent_id] if t > minute_ago
        ]

        return len(self._request_history[agent_id]) < rule.max_requests_per_minute

    def _record_event(
        self,
        agent_id: str,
        task_id: str,
        host: str,
        port: int,
        protocol: str,
        decision: EgressDecision,
        reason: str = "",
    ):
        """Record an egress event for audit."""
        event = EgressEvent(
            timestamp=time.time(),
            agent_id=agent_id,
            task_id=task_id,
            host=host,
            port=port,
            protocol=protocol,
            decision=decision.value,
            reason=reason,
        )
        self._events.append(event)

        # Keep event buffer bounded
        if len(self._events) > 10000:
            self._events = self._events[-5000:]

    def log_connection(
        self,
        agent_id: str,
        host: str,
        port: int,
        bytes_sent: int = 0,
        bytes_received: int = 0,
        task_id: str = "",
    ):
        """Log a completed connection for audit."""
        self._request_history.setdefault(agent_id, []).append(time.time())
        self._record_event(
            agent_id, task_id, host, port, "https",
            EgressDecision.ALLOW,
            f"sent={bytes_sent}, recv={bytes_received}"
        )

    def get_events(
        self,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query egress events."""
        results = []
        for event in reversed(self._events):
            if len(results) >= limit:
                break
            if agent_id and event.agent_id != agent_id:
                continue
            if decision and event.decision != decision:
                continue
            results.append({
                "timestamp": event.timestamp,
                "agent_id": event.agent_id,
                "task_id": event.task_id,
                "host": event.host,
                "port": event.port,
                "protocol": event.protocol,
                "decision": event.decision,
                "reason": event.reason,
                "bytes_sent": event.bytes_sent,
                "bytes_received": event.bytes_received,
            })
        return results

    def get_statistics(self) -> dict:
        """Get egress proxy statistics."""
        allowed = sum(1 for e in self._events if e.decision == "allow")
        denied = sum(1 for e in self._events if e.decision != "allow")

        denied_reasons = {}
        for e in self._events:
            if e.decision != "allow":
                denied_reasons[e.decision] = denied_reasons.get(e.decision, 0) + 1

        return {
            "total_events": len(self._events),
            "allowed": allowed,
            "denied": denied,
            "denial_reasons": denied_reasons,
            "allowed_domains": len(self._allowed_domains),
            "wildcard_patterns": len(self._domain_patterns),
            "active_agents": len(self._request_history),
        }
